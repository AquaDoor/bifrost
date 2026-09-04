package aquadoorpii

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Presidio analyzer/anonymizer HTTP client (Bifrost unified gateway, #1780 §7.5).
//
// Every method FAILS CLOSED: any anomaly (dial/timeout error, non-2xx, non-JSON, or a Presidio
// {"error":...} body) returns a non-nil error, which the PreLLMHook turns into a blocking
// short-circuit. Mirrors LiteLLM's presidio.py control flow: "PII protection configured ⇒ any
// analyzer/anonymizer anomaly blocks the request".

// AnalyzerResult is one RecognizerResult from POST /analyze.
type AnalyzerResult struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

type presidioClient struct {
	analyzeURL   string
	anonymizeURL string
	language     string
	httpClient   *http.Client
}

func newPresidioClient(analyzeURL, anonymizeURL, language string, hc *http.Client) *presidioClient {
	return &presidioClient{
		analyzeURL:   analyzeURL,
		anonymizeURL: anonymizeURL,
		language:     language,
		httpClient:   hc,
	}
}

func (p *presidioClient) postJSON(ctx context.Context, url string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("presidio unreachable: %w", err) // dial/timeout → fail closed
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("presidio HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "json") {
		return nil, fmt.Errorf("presidio non-JSON content-type %q", ct)
	}
	return data, nil
}

// analyze returns the detected entities, or an error (fail-closed) on any anomaly.
func (p *presidioClient) analyze(ctx context.Context, text string, entities []string) ([]AnalyzerResult, error) {
	payload := map[string]any{"text": text, "language": p.language}
	if len(entities) > 0 {
		payload["entities"] = entities
	}
	data, err := p.postJSON(ctx, p.analyzeURL, payload)
	if err != nil {
		return nil, err
	}
	// A dict body carrying "error" is a Presidio failure, not an empty result → fail closed.
	var errObj struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &errObj) == nil && errObj.Error != "" {
		return nil, fmt.Errorf("presidio analyze error: %s", errObj.Error)
	}
	var results []AnalyzerResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("presidio analyze: unexpected body: %s", truncate(string(data), 200))
	}
	return results, nil
}

// anonymize returns the redacted text (default operator replaces each entity with <TYPE>), or an
// error (fail-closed) on any anomaly.
func (p *presidioClient) anonymize(ctx context.Context, text string, results []AnalyzerResult) (string, error) {
	payload := map[string]any{"text": text, "analyzer_results": results}
	data, err := p.postJSON(ctx, p.anonymizeURL, payload)
	if err != nil {
		return "", err
	}
	var out struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("presidio anonymize: unexpected body: %s", truncate(string(data), 200))
	}
	return out.Text, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
