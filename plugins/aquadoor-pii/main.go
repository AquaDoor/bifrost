// Package aquadoorpii is the AquaDoor fail-closed PII guardrail — an in-tree Bifrost LLMPlugin that
// redacts RU/PII from every outbound prompt before off-shore LLM egress (152-ФЗ, posture C /
// #1780 §7.5). Recognition runs IN-PROCESS (recognizers.go: checksum-gated RU_INN/RU_OGRN/
// RU_OGRNIP + context-gated RU_PHONE/RU_PASSPORT) — there is no external Presidio service. That
// is the whole point: no separate Python/spaCy image to deploy or keep alive (no swarm RAM cost),
// and no network hop that can time out and fail OPEN.
//
// CRITICAL — Bifrost plugin errors FAIL OPEN (they are logged as warnings, not returned to the
// caller — core/schemas/plugin.go). To fail CLOSED we NEVER return a bare Go error from
// PreLLMHook; every block path returns a *LLMPluginShortCircuit whose Error is set with
// AllowFallbacks=false (no fallback provider gets the un-redacted prompt). In-process recognition
// cannot be "unavailable", so the former network-unreachable fail-closed path is gone by design;
// the remaining fail-closed blocks (unsupported shape, raw passthrough, BLOCK entities) stay.
package aquadoorpii

import (
	"fmt"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// Per-entity action. "allow" leaves the value untouched (it is not personal data — e.g. a
// legal-entity INN/OGRN, the payload of B2B tender/dealer analysis); "redact" masks it as <TYPE>
// before egress (the §7.5 primary mechanism for personal data); "block" refuses the whole request.
const (
	actionAllow  = "allow"
	actionRedact = "redact"
	actionBlock  = "block"
)

// Config for the PII plugin. Actions maps an entity type → action (allow|redact|block); a type not
// listed uses DefaultAction (default "redact", so an unclassified detection fails safe by masking).
// Entities, when non-empty, restricts recognition to those types. Language is retained for config
// compatibility (recognizers are RU).
type Config struct {
	Language      string
	Entities      []string
	Actions       map[string]string
	DefaultAction string
}

type Plugin struct {
	cfg Config
}

// New builds the plugin. Language defaults to "ru"; DefaultAction to "redact".
func New(cfg Config) *Plugin {
	if cfg.Language == "" {
		cfg.Language = "ru"
	}
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = actionRedact
	}
	return &Plugin{cfg: cfg}
}

// actionFor returns the configured action for an entity type (case-insensitive value), or the
// default. An unknown action value falls back to the default (fail-safe — never silently allow).
func (p *Plugin) actionFor(entityType string) string {
	a := p.cfg.DefaultAction
	if v, ok := p.cfg.Actions[entityType]; ok {
		a = strings.ToLower(strings.TrimSpace(v))
	}
	switch a {
	case actionAllow, actionRedact, actionBlock:
		return a
	default:
		return actionRedact
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
) (outReq *schemas.BifrostRequest, sc *schemas.LLMPluginShortCircuit, err error) {
	// Fail-closed panic guard (#1780 §7.5 / G010): a panic anywhere in redaction must NEVER let an
	// un-redacted prompt egress, and must not crash the gateway. Recover → BLOCK the request
	// (fail-closed short-circuit, no fallback), so a redaction bug degrades to "denied", never "leaked".
	defer func() {
		if r := recover(); r != nil {
			outReq = req
			sc = blockShortCircuit("pii_panic", fmt.Sprintf("PII guardrail panicked: %v (blocked fail-closed)", r))
			err = nil
		}
	}()
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
	// Fail-closed #2 — ALLOW-LIST (block-by-default, #1813). Only chat / text-completion / embedding /
	// image-generation are inspected + redacted (collectTextSpans below). Content-free metadata ops
	// (list / retrieve / delete / cancel) egress no user text and pass. EVERY other content-bearing
	// shape — AND any NEW/unrecognized shape a Bifrost upgrade adds — is BLOCKED, not silently leaked.
	// This replaced a deny-list that failed OPEN on any shape it did not enumerate (a new content-
	// bearing request type would have egressed un-redacted). Non-text PII inside a COVERED shape (an
	// image content-block in a chat message, an image in image-generation) is the documented accepted
	// residual (#1813 followup). Extend collectTextSpans + move a shape to piiRedact as B7 covers it.
	switch requestDisposition(req) {
	case piiBlock:
		return req, blockShortCircuit("pii_unsupported_shape",
			"PII guardrail cannot inspect this request shape; blocked (fail-closed)"), nil
	case piiAllow:
		return req, nil, nil // content-free operational request — no user text egresses
	}
	// piiRedact — a covered content-bearing shape; fall through to span redaction below.
	// A RAG embedding is NEVER blocked (§7.5 review — a blocked embedding would silently break
	// retrieval); a block-action entity is redacted instead on that path.
	blockAllowed := req.EmbeddingRequest == nil
	for _, span := range collectTextSpans(req) {
		text := span.get()
		if text == "" {
			continue
		}
		// In-process recognition (recognizers.go): deterministic, no I/O, cannot fail open.
		results := recognize(text, p.cfg.Entities)
		var toRedact []AnalyzerResult
		for _, r := range results {
			switch p.actionFor(r.EntityType) {
			case actionBlock:
				if blockAllowed {
					return req, blockShortCircuit("pii_blocked", "blocked PII entity: "+r.EntityType), nil
				}
				toRedact = append(toRedact, r) // embedding: degrade block→redact rather than drop retrieval
			case actionAllow:
				// Not personal data (e.g. a legal-entity INN/OGRN) — leave the value intact.
			default: // redact
				toRedact = append(toRedact, r)
			}
		}
		if len(toRedact) > 0 {
			span.set(anonymize(text, toRedact))
		}
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

// piiDisposition is how the guardrail treats a request shape. The zero value is piiBlock, so any
// code path that forgets to classify a shape fails CLOSED by construction.
type piiDisposition int

const (
	piiBlock  piiDisposition = iota // fail-closed default: content-bearing-uninspected OR unknown
	piiRedact                       // covered content-bearing shape → collectTextSpans redacts it
	piiAllow                        // content-free operational shape → no user text egresses
)

// requestDisposition classifies a request for the PII guardrail as an ALLOW-LIST (block-by-default,
// #1813). It replaced a deny-list that returned "allow" for every shape it did not enumerate — so a
// content-bearing request type NOT on that list (FileUpload, VideoRemix, CachedContent create/update,
// Batch/Container create, raw Passthrough, …) OR any NEW shape a Bifrost upgrade adds egressed
// un-redacted (silent fail-OPEN). Now:
//   - piiRedact: chat / text-completion / embedding / image-generation — collectTextSpans redacts.
//   - piiAllow: content-free ops (list / retrieve / delete / cancel / input-items / results /
//     download / content) — id + metadata only; no user PII text egresses.
//   - piiBlock (default): every other content-bearing shape this text guardrail cannot inspect
//     (responses-create, count-tokens, compaction, rerank, ocr, speech, transcription, image-edit,
//     image-variation, video generation/edit/remix, file/container-file upload, cached-content
//     create/update, batch/container create, passthrough) AND any unrecognized/new shape → blocked
//     loudly rather than leaked. NON-TEXT PII inside a covered shape (image content-blocks, the
//     image-generation image output) is the documented accepted residual (#1813 followup).
//
// As B7 adds coverage, extend collectTextSpans and move the shape from the default into piiRedact.
func requestDisposition(req *schemas.BifrostRequest) piiDisposition {
	switch {
	case req.ChatRequest != nil,
		req.TextCompletionRequest != nil,
		req.EmbeddingRequest != nil,
		req.ImageGenerationRequest != nil:
		return piiRedact

	case req.ListModelsRequest != nil,
		req.ResponsesRetrieveRequest != nil,
		req.ResponsesDeleteRequest != nil,
		req.ResponsesCancelRequest != nil,
		req.ResponsesInputItemsRequest != nil,
		req.VideoRetrieveRequest != nil,
		req.VideoDownloadRequest != nil,
		req.VideoListRequest != nil,
		req.VideoDeleteRequest != nil,
		req.FileListRequest != nil,
		req.FileRetrieveRequest != nil,
		req.FileDeleteRequest != nil,
		req.FileContentRequest != nil,
		req.CachedContentListRequest != nil,
		req.CachedContentRetrieveRequest != nil,
		req.CachedContentDeleteRequest != nil,
		req.BatchListRequest != nil,
		req.BatchRetrieveRequest != nil,
		req.BatchCancelRequest != nil,
		req.BatchResultsRequest != nil,
		req.BatchDeleteRequest != nil,
		req.ContainerListRequest != nil,
		req.ContainerRetrieveRequest != nil,
		req.ContainerDeleteRequest != nil,
		req.ContainerFileListRequest != nil,
		req.ContainerFileRetrieveRequest != nil,
		req.ContainerFileContentRequest != nil,
		req.ContainerFileDeleteRequest != nil:
		return piiAllow

	default:
		return piiBlock
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
