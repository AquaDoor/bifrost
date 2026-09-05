package aquadoorpii

import (
	"context"
	"testing"
	"time"

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

func plugin(block map[string]bool) *Plugin {
	return New(Config{Language: "ru", BlockEntities: block})
}

// A valid INN with no BLOCK config → redacted in-process to <RU_INN>.
func TestPII_RedactsDetectedEntity(t *testing.T) {
	p := plugin(nil)
	req := chatReq("мой ИНН 7830002293 вот")
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sc != nil {
		t.Fatalf("unexpected short-circuit: %+v", sc)
	}
	if got := *out.ChatRequest.Input[0].Content.ContentStr; got != "мой ИНН <RU_INN> вот" {
		t.Errorf("not redacted: %q", got)
	}
}

// A random 10-digit number that FAILS the INN checksum must NOT be detected as an INN (the
// checksum is the gate, not the regex) — and with no passport context it is not a passport either.
func TestPII_ChecksumGate_RandomNumberNotRedacted(t *testing.T) {
	p := plugin(nil)
	req := chatReq("заказ 1234567890 готов")
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("expected passthrough, sc=%v err=%v", sc, err)
	}
	if got := *out.ChatRequest.Input[0].Content.ContentStr; got != "заказ 1234567890 готов" {
		t.Errorf("random non-INN number should be untouched, got %q", got)
	}
}

func TestPII_BlocksConfiguredEntity(t *testing.T) {
	p := plugin(map[string]bool{"RU_INN": true})
	// A valid INN is a BLOCK entity → the whole request is refused (fail-closed).
	_, sc, _ := p.PreLLMHook(nil, chatReq("ИНН 7830002293"))
	if sc == nil || sc.Error == nil {
		t.Fatal("expected a block for the configured BLOCK entity")
	}
	if sc.Error.Error == nil || sc.Error.Error.Code == nil || *sc.Error.Error.Code != "pii_blocked" {
		t.Errorf("expected code=pii_blocked, got %+v", sc.Error.Error)
	}
}

// Passport is context-gated: a bare 10-digit-shaped number with NO passport context is not flagged
// (avoids redacting every order number), but WITH context it is a blocked passport.
func TestPII_Passport_ContextGated(t *testing.T) {
	block := map[string]bool{"RU_PASSPORT": true}
	// No context → not detected → passes through.
	if _, sc, _ := plugin(block).PreLLMHook(nil, chatReq("номер 12 34 567890")); sc != nil {
		t.Fatalf("bare number without passport context must not block, got %+v", sc)
	}
	// With context → blocked.
	_, sc, _ := plugin(block).PreLLMHook(nil, chatReq("паспорт серия 12 34 567890"))
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || sc.Error.Error.Code == nil ||
		*sc.Error.Error.Code != "pii_blocked" {
		t.Fatalf("passport with context must block, got %+v", sc)
	}
}

func TestPII_PassthroughWhenNoEntities(t *testing.T) {
	p := plugin(nil)
	req := chatReq("no pii here")
	_, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("expected passthrough, sc=%v err=%v", sc, err)
	}
	if *req.ChatRequest.Input[0].Content.ContentStr != "no pii here" {
		t.Error("text should be unchanged when no entities detected")
	}
}

// The RAG embedding path MUST be redacted, never blocked (#1780 review) — even for a BLOCK-listed
// entity, the embedding path only ever redacts (blocking config applies to chat/completion).
func TestPII_RedactsEmbeddingInput(t *testing.T) {
	p := plugin(nil)
	req := &schemas.BifrostRequest{
		EmbeddingRequest: &schemas.BifrostEmbeddingRequest{
			Input: &schemas.EmbeddingInput{Text: schemas.Ptr("мой ИНН 7830002293 тут")},
		},
	}
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("embedding must be redacted, not blocked: sc=%v err=%v", sc, err)
	}
	if got := *out.EmbeddingRequest.Input.Text; got != "мой ИНН <RU_INN> тут" {
		t.Errorf("embedding text not redacted: %q", got)
	}
}

func TestPII_RedactsImageGenPrompt(t *testing.T) {
	p := plugin(nil)
	req := &schemas.BifrostRequest{
		ImageGenerationRequest: &schemas.BifrostImageGenerationRequest{
			Input: &schemas.ImageGenerationInput{Prompt: "портрет ИНН 7830002293"},
		},
	}
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("image-gen prompt must be redacted, not blocked: sc=%v err=%v", sc, err)
	}
	if got := out.ImageGenerationRequest.Input.Prompt; got != "портрет ИНН <RU_INN>" {
		t.Errorf("image prompt not redacted: %q", got)
	}
}

// A prompt-bearing shape collectTextSpans doesn't cover must fail closed (block), not silently
// forward un-redacted (the #1780-review fail-OPEN).
func TestPII_BlocksUnsupportedShape(t *testing.T) {
	p := plugin(nil)
	req := &schemas.BifrostRequest{RerankRequest: &schemas.BifrostRerankRequest{}}
	_, sc, err := p.PreLLMHook(nil, req)
	if err != nil {
		t.Fatalf("must not return a bare error (fails open): %v", err)
	}
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || sc.Error.Error.Code == nil ||
		*sc.Error.Error.Code != "pii_unsupported_shape" {
		t.Fatalf("expected a fail-closed block for an unsupported shape, got %+v", sc)
	}
	if sc.Error.AllowFallbacks == nil || *sc.Error.AllowFallbacks {
		t.Error("expected AllowFallbacks=false")
	}
}

// A raw request-body passthrough egresses the ORIGINAL bytes span redaction never touches; block it.
func TestPII_BlocksRawPassthrough(t *testing.T) {
	p := plugin(nil)
	bctx := schemas.NewBifrostContextWithValue(context.Background(), time.Time{}, "seed", "x")
	bctx.SetValue(schemas.BifrostContextKeyUseRawRequestBody, true)
	_, sc, err := p.PreLLMHook(bctx, chatReq("мой ИНН 7830002293"))
	if err != nil {
		t.Fatalf("must not return a bare error: %v", err)
	}
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || sc.Error.Error.Code == nil ||
		*sc.Error.Error.Code != "pii_raw_passthrough_unredactable" {
		t.Fatalf("expected a fail-closed block on raw passthrough, got %+v", sc)
	}
}
