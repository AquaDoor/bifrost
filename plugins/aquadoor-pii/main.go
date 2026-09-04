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
	_ *schemas.BifrostContext,
	req *schemas.BifrostRequest,
) (*schemas.BifrostRequest, *schemas.LLMPluginShortCircuit, error) {
	if req == nil {
		return req, nil, nil
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
	return spans
}
