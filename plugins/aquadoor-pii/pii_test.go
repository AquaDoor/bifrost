package aquadoorpii

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func chatReq(text string) *schemas.BifrostRequest {
	return &schemas.BifrostRequest{
		RequestType: schemas.ChatCompletionRequest,
		ChatRequest: &schemas.BifrostChatRequest{
			Input: []schemas.ChatMessage{
				{
					Role:    schemas.ChatMessageRoleUser,
					Content: &schemas.ChatMessageContent{ContentStr: schemas.Ptr(text)},
				},
			},
		},
	}
}

func jsonHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func pluginFor(t *testing.T, analyze, anonymize http.HandlerFunc, block map[string]bool) *Plugin {
	a := httptest.NewServer(analyze)
	n := httptest.NewServer(anonymize)
	t.Cleanup(func() { a.Close(); n.Close() })
	return New(Config{
		AnalyzerURL:   a.URL,
		AnonymizerURL: n.URL,
		Language:      "ru",
		TimeoutMS:     2000,
		BlockEntities: block,
	})
}

func TestPII_RedactsDetectedEntity(t *testing.T) {
	p := pluginFor(t,
		jsonHandler(200, `[{"entity_type":"RU_INN","start":8,"end":18,"score":1.0}]`),
		jsonHandler(200, `{"text":"мой ИНН <RU_INN>"}`), nil)
	req := chatReq("мой ИНН 7830002293")
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sc != nil {
		t.Fatalf("unexpected short-circuit: %+v", sc)
	}
	if got := *out.ChatRequest.Input[0].Content.ContentStr; got != "мой ИНН <RU_INN>" {
		t.Errorf("not redacted: %q", got)
	}
}

func TestPII_FailsClosedOnPresidioDown(t *testing.T) {
	p := pluginFor(t, jsonHandler(500, `{"error":"boom"}`), jsonHandler(200, `{}`), nil)
	req := chatReq("мой ИНН 7830002293")
	_, sc, err := p.PreLLMHook(nil, req)
	if err != nil {
		t.Fatalf("plugin must not return a bare error (fails open): %v", err)
	}
	if sc == nil || sc.Error == nil {
		t.Fatal("expected a blocking short-circuit when Presidio is down")
	}
	if sc.Error.StatusCode == nil || *sc.Error.StatusCode != 403 {
		t.Error("expected 403 status")
	}
	if sc.Error.AllowFallbacks == nil || *sc.Error.AllowFallbacks {
		t.Error("expected AllowFallbacks=false (no fallback sees the un-redacted prompt)")
	}
	if *req.ChatRequest.Input[0].Content.ContentStr != "мой ИНН 7830002293" {
		t.Error("text must be untouched on a block (request is dropped, not forwarded)")
	}
}

func TestPII_FailsClosedOnErrorBody(t *testing.T) {
	// 200 but a dict {"error":...} is a Presidio failure, not an empty result → fail closed.
	p := pluginFor(t, jsonHandler(200, `{"error":"No text provided"}`), jsonHandler(200, `{}`), nil)
	_, sc, _ := p.PreLLMHook(nil, chatReq("hi"))
	if sc == nil {
		t.Fatal("expected a block on an analyzer error body")
	}
}

func TestPII_BlocksConfiguredEntity(t *testing.T) {
	p := pluginFor(t,
		jsonHandler(200, `[{"entity_type":"RU_PASSPORT","start":0,"end":10,"score":0.9}]`),
		jsonHandler(200, `{"text":"x"}`), map[string]bool{"RU_PASSPORT": true})
	_, sc, _ := p.PreLLMHook(nil, chatReq("12 34 567890"))
	if sc == nil || sc.Error == nil {
		t.Fatal("expected a block for the configured BLOCK entity")
	}
	if sc.Error.Error == nil || sc.Error.Error.Code == nil || *sc.Error.Error.Code != "pii_blocked" {
		t.Errorf("expected code=pii_blocked, got %+v", sc.Error.Error)
	}
}

func TestPII_PassthroughWhenNoEntities(t *testing.T) {
	p := pluginFor(t, jsonHandler(200, `[]`), jsonHandler(200, `{}`), nil)
	req := chatReq("no pii here")
	_, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("expected passthrough, sc=%v err=%v", sc, err)
	}
	if *req.ChatRequest.Input[0].Content.ContentStr != "no pii here" {
		t.Error("text should be unchanged when no entities detected")
	}
}
