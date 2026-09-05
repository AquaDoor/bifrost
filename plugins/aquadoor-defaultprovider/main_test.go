package aquadoordefaultprovider

import (
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestDefaultsEmptyProviderOnChat(t *testing.T) {
	p := NewPlugin("aquadoor-llm")
	req := &schemas.BifrostRequest{ChatRequest: &schemas.BifrostChatRequest{Model: "zai/glm-5.3"}}
	if err := p.PreRequestHook(nil, req); err != nil {
		t.Fatal(err)
	}
	if req.ChatRequest.Provider != "aquadoor-llm" {
		t.Errorf("empty provider must default to aquadoor-llm, got %q", req.ChatRequest.Provider)
	}
}

func TestDoesNotOverrideExplicitProvider(t *testing.T) {
	p := NewPlugin("aquadoor-llm")
	// image-gen keeps its explicit aquadoor-llm/ prefix → provider already resolved to something.
	req := &schemas.BifrostRequest{ImageGenerationRequest: &schemas.BifrostImageGenerationRequest{Provider: "openai", Model: "gpt-image-1"}}
	if err := p.PreRequestHook(nil, req); err != nil {
		t.Fatal(err)
	}
	if req.ImageGenerationRequest.Provider != "openai" {
		t.Errorf("must not override an explicit provider, got %q", req.ImageGenerationRequest.Provider)
	}
}

func TestDefaultsEmbeddings(t *testing.T) {
	p := NewPlugin("aquadoor-llm")
	req := &schemas.BifrostRequest{EmbeddingRequest: &schemas.BifrostEmbeddingRequest{Model: "alibaba/qwen3-embedding-4b"}}
	if err := p.PreRequestHook(nil, req); err != nil {
		t.Fatal(err)
	}
	if req.EmbeddingRequest.Provider != "aquadoor-llm" {
		t.Errorf("empty embeddings provider must default, got %q", req.EmbeddingRequest.Provider)
	}
}

func TestEmptyProviderConfigIsNoOp(t *testing.T) {
	p := NewPlugin("") // self-disabled
	req := &schemas.BifrostRequest{ChatRequest: &schemas.BifrostChatRequest{Model: "zai/glm-5.3"}}
	if err := p.PreRequestHook(nil, req); err != nil {
		t.Fatal(err)
	}
	if req.ChatRequest.Provider != "" {
		t.Errorf("empty config must be a no-op, got %q", req.ChatRequest.Provider)
	}
}
