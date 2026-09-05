// Package aquadoordefaultprovider routes bare/unknown-prefix model names to the AquaDoor LLM
// provider (Bifrost unified gateway, #1780 §7.7 / #1801 / fablize G006).
//
// WHY: Bifrost routes an LLM request by the model's provider prefix. LibreChat (and its RAG/memory)
// send bare or vendor-prefixed model ids like "zai/glm-5.3", "moonshotai/kimi-k2.6",
// "alibaba/qwen3-embedding-4b" — none of which are Bifrost-known providers, so ParseModelString
// collapses them to an EMPTY provider and validateRequestAfterPreRequestHooks then hard-rejects the
// request ("provider auto-resolve"). This plugin's PreRequestHook runs BEFORE that validation (and
// before governance) and, when the resolved provider is empty, sets it to the single configured
// AquaDoor provider — so LibreChat can keep clean bare model names (no per-model prefixing, no
// LibreChat rebuild) while all LLM egress still routes through Bifrost (aquadoor-pii + governance,
// 152-ФЗ). An explicit prefix (e.g. "aquadoor-llm/openai/gpt-image-1") already yields a non-empty
// provider, so the hook is inert for it — image-gen keeps its explicit prefix to avoid mis-routing
// "openai/…" to a real openai provider.
package aquadoordefaultprovider

import (
	"github.com/maximhq/bifrost/core/schemas"
)

// Config is the plugin config (config.json): the provider to default to when a request resolves to
// none. Empty → the hook self-disables.
type Config struct {
	Provider string `json:"Provider"`
}

// Plugin sets a default provider on requests that resolve to none.
type Plugin struct {
	provider schemas.ModelProvider
}

var _ schemas.BasePlugin = (*Plugin)(nil)

// New builds the plugin from config (the plugins.go registration path).
func New(cfg Config) *Plugin { return NewPlugin(cfg.Provider) }

// NewPlugin builds the plugin for the given default provider (e.g. "aquadoor-llm"). An empty
// provider makes the hook a no-op (self-disabled), matching the rest of the AquaDoor plugins.
func NewPlugin(provider string) *Plugin {
	return &Plugin{provider: schemas.ModelProvider(provider)}
}

func (p *Plugin) GetName() string { return "aquadoor-default-provider" }
func (p *Plugin) Cleanup() error  { return nil }

// PreRequestHook sets the default provider on the active sub-request when it resolved to none
// (bare/unknown-prefix model). BifrostRequest is a union of per-shape sub-requests, each carrying its
// own Provider — so we set it on whichever content-bearing shape is present (the ones LibreChat uses:
// chat, embeddings, image generation, plus their close variants for robustness). Runs before
// validateRequestAfterPreRequestHooks and before governance, so the defaulted provider is what both
// see. Never overrides an explicit provider (an explicit prefix already yields a non-empty provider).
func (p *Plugin) PreRequestHook(_ *schemas.BifrostContext, req *schemas.BifrostRequest) error {
	if p.provider == "" || req == nil {
		return nil
	}
	provider, _, _ := req.GetRequestFields()
	if provider != "" {
		return nil
	}
	switch {
	case req.ChatRequest != nil:
		req.ChatRequest.Provider = p.provider
	case req.TextCompletionRequest != nil:
		req.TextCompletionRequest.Provider = p.provider
	case req.ResponsesRequest != nil:
		req.ResponsesRequest.Provider = p.provider
	case req.EmbeddingRequest != nil:
		req.EmbeddingRequest.Provider = p.provider
	case req.ImageGenerationRequest != nil:
		req.ImageGenerationRequest.Provider = p.provider
	case req.ImageEditRequest != nil:
		req.ImageEditRequest.Provider = p.provider
	case req.ImageVariationRequest != nil:
		req.ImageVariationRequest.Provider = p.provider
	}
	return nil
}
