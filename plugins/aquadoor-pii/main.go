// Package aquadoorpii is the AquaDoor fail-closed PII guardrail — an in-tree Bifrost LLMPlugin that
// redacts RU/PII from every outbound prompt before off-shore LLM egress (152-ФЗ, posture C /
// #1780 §7.5). It calls the forked Presidio analyzer/anonymizer (infra/presidio-ru, with the
// checksum-gated RU recognizers).
//
// CRITICAL — Bifrost plugin errors FAIL OPEN (they are logged as warnings, not returned to the
// caller — core/schemas/plugin.go). To fail CLOSED we NEVER return a bare Go error from
// PreLLMHook; every block path returns a *LLMPluginShortCircuit whose Error is set with
// AllowFallbacks=false (no fallback provider gets the un-redacted prompt).
package aquadoorpii

import (
	"context"
	"net/http"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// Config for the PII plugin. BlockEntities lists entity types that BLOCK the whole request
// (vs the default: redact/mask and continue).
type Config struct {
	AnalyzerURL   string
	AnonymizerURL string
	Language      string
	TimeoutMS     int
	Entities      []string
	BlockEntities map[string]bool
}

type Plugin struct {
	presidio *presidioClient
	cfg      Config
	timeout  time.Duration
}

// New builds the plugin. Language defaults to "ru", timeout to 800ms.
func New(cfg Config) *Plugin {
	if cfg.Language == "" {
		cfg.Language = "ru"
	}
	if cfg.TimeoutMS == 0 {
		cfg.TimeoutMS = 800
	}
	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	hc := &http.Client{Timeout: timeout}
	return &Plugin{
		presidio: newPresidioClient(cfg.AnalyzerURL, cfg.AnonymizerURL, cfg.Language, hc),
		cfg:      cfg,
		timeout:  timeout,
	}
}

func (p *Plugin) GetName() string { return "aquadoor-pii" }
func (p *Plugin) Cleanup() error  { return nil }

func (p *Plugin) PreRequestHook(_ *schemas.BifrostContext, _ *schemas.BifrostRequest) error {
	return nil
}

// PreLLMHook redacts every outbound text span, or blocks (fail-closed) on any Presidio anomaly
// or a configured BLOCK entity.
func (p *Plugin) PreLLMHook(
	bctx *schemas.BifrostContext,
	req *schemas.BifrostRequest,
) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	if req == nil {
		return req, nil, nil
	}
	// Fail-closed #1 — raw request-body passthrough: the ORIGINAL client bytes egress (the
	// parsed-request span mutation below never touches them), so this text guardrail cannot redact
	// the request. Block it. Set by the Anthropic/Gemini native passthrough integrations (#1780 review).
	if bctx != nil {
		if raw, ok := bctx.Value(schemas.BifrostContextKeyUseRawRequestBody).(bool); ok && raw {
			return req, blockShortCircuit("pii_raw_passthrough_unredactable",
				"raw request-body passthrough egresses un-redacted bytes; blocked (fail-closed)"), nil
		}
	}
	// Fail-closed #2 — a prompt/content-bearing request shape this guardrail does not redact. Chat,
	// text-completion, embedding (RAG) and image-generation ARE covered by collectTextSpans below;
	// every other content-bearing shape would otherwise egress un-redacted (silent fail-OPEN, #1780
	// review). Block it loudly rather than leak. Extend collectTextSpans + unsupportedShape together
	// as B7 adds coverage.
	if shape := unsupportedShape(req); shape != "" {
		return req, blockShortCircuit("pii_unsupported_shape",
			"PII guardrail cannot redact a "+shape+" request; blocked (fail-closed)"), nil
	}
	for _, span := range collectTextSpans(req) {
		text := span.get()
		if text == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
		results, err := p.presidio.analyze(ctx, text, p.cfg.Entities)
		if err != nil {
			cancel()
			return req, blockShortCircuit("pii_guardrail_unavailable",
				"PII guardrail could not verify the request; blocked (fail-closed): "+err.Error()), nil
		}
		for _, r := range results {
			if p.cfg.BlockEntities[r.EntityType] {
				cancel()
				return req, blockShortCircuit("pii_blocked", "blocked PII entity: "+r.EntityType), nil
			}
		}
		if len(results) > 0 {
			red, err := p.presidio.anonymize(ctx, text, results)
			if err != nil {
				cancel()
				return req, blockShortCircuit("pii_guardrail_unavailable",
					"PII anonymize failed; blocked (fail-closed): "+err.Error()), nil
			}
			span.set(red)
		}
		cancel()
	}
	return req, nil, nil
}

func (p *Plugin) PostLLMHook(
	_ *schemas.BifrostContext,
	resp *schemas.BifrostResponse,
	bifrostErr *schemas.BifrostError,
) (*schemas.BifrostResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}

func blockShortCircuit(code, msg string) *schemas.LLMPluginShortCircuit {
	return &schemas.LLMPluginShortCircuit{
		Error: &schemas.BifrostError{
			StatusCode:     schemas.Ptr(403),
			AllowFallbacks: schemas.Ptr(false), // never let a fallback provider see the un-redacted prompt
			Error: &schemas.ErrorField{
				Type:    schemas.Ptr("pii_guardrail"),
				Code:    schemas.Ptr(code),
				Message: msg,
			},
		},
	}
}

// unsupportedShape names a prompt/content-bearing request shape this guardrail does NOT redact (so
// PreLLMHook must fail closed), or "" when the request is either fully covered by collectTextSpans
// (chat, text-completion, embedding, image-generation) or is a content-free operational request
// (list-models, responses retrieve/delete/cancel/input-items, video retrieve/download, image
// variation) that egresses no user PII text. The blocked shapes carry user text/content off-shore
// that this text guardrail cannot yet inspect — a loud block is the fail-closed choice over a
// silent leak. Extend collectTextSpans + this switch together as B7 adds coverage.
func unsupportedShape(req *schemas.BifrostRequest) string {
	switch {
	case req.ResponsesRequest != nil:
		return "responses"
	case req.CountTokensRequest != nil:
		return "count-tokens"
	case req.RerankRequest != nil:
		return "rerank"
	case req.SpeechRequest != nil:
		return "speech"
	case req.TranscriptionRequest != nil:
		return "transcription"
	case req.ImageEditRequest != nil:
		return "image-edit"
	case req.VideoGenerationRequest != nil:
		return "video-generation"
	case req.VideoEditRequest != nil:
		return "video-edit"
	case req.OCRRequest != nil:
		return "ocr"
	case req.CompactionRequest != nil:
		return "compaction"
	}
	return ""
}

// textSpan is a mutable handle to one outbound text field.
type textSpan struct {
	get func() string
	set func(string)
}

// collectTextSpans returns mutable handles to every user-visible outbound text field across the
// supported request shapes (chat messages incl. text content-blocks, text-completion prompts).
func collectTextSpans(req *schemas.BifrostRequest) []textSpan {
	var spans []textSpan
	if req.ChatRequest != nil {
		for i := range req.ChatRequest.Input {
			msg := &req.ChatRequest.Input[i]
			if msg.Content == nil {
				continue
			}
			if msg.Content.ContentStr != nil {
				cs := msg.Content.ContentStr
				spans = append(spans, textSpan{get: func() string { return *cs }, set: func(s string) { *cs = s }})
			}
			for j := range msg.Content.ContentBlocks {
				blk := &msg.Content.ContentBlocks[j]
				if blk.Type == schemas.ChatContentBlockTypeText && blk.Text != nil {
					bt := blk.Text
					spans = append(spans, textSpan{get: func() string { return *bt }, set: func(s string) { *bt = s }})
				}
			}
		}
	}
	if req.TextCompletionRequest != nil && req.TextCompletionRequest.Input != nil {
		in := req.TextCompletionRequest.Input
		if in.PromptStr != nil {
			ps := in.PromptStr
			spans = append(spans, textSpan{get: func() string { return *ps }, set: func(s string) { *ps = s }})
		}
		for k := range in.PromptArray {
			idx := k
			spans = append(spans, textSpan{
				get: func() string { return in.PromptArray[idx] },
				set: func(s string) { in.PromptArray[idx] = s },
			})
		}
	}
	// Embedding (the RAG path — user documents/queries embedded off-shore; MUST be redacted, never
	// blocked): Text (single) + Texts (batch).
	if req.EmbeddingRequest != nil && req.EmbeddingRequest.Input != nil {
		in := req.EmbeddingRequest.Input
		if in.Text != nil {
			et := in.Text
			spans = append(spans, textSpan{get: func() string { return *et }, set: func(s string) { *et = s }})
		}
		for k := range in.Texts {
			idx := k
			spans = append(spans, textSpan{
				get: func() string { return in.Texts[idx] },
				set: func(s string) { in.Texts[idx] = s },
			})
		}
	}
	// Image generation (the image prompt — a text description that can carry PII; redact it).
	if req.ImageGenerationRequest != nil && req.ImageGenerationRequest.Input != nil {
		gi := req.ImageGenerationRequest.Input
		spans = append(spans, textSpan{get: func() string { return gi.Prompt }, set: func(s string) { gi.Prompt = s }})
	}
	return spans
}
