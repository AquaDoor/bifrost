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

// plugin builds a plugin with the AquaDoor default policy (legal-entity IDs allowed, individual PII
// redacted), overlaying any per-test action overrides.
func plugin(actions map[string]string) *Plugin {
	base := map[string]string{
		entityINNLegal: actionAllow, entityOGRN: actionAllow,
		entityINN: actionRedact, entityOGRNIP: actionRedact,
		entityPhone: actionRedact, entityPassport: actionRedact,
	}
	for k, v := range actions {
		base[k] = v
	}
	return New(Config{Language: "ru", Actions: base})
}

// The AquaDoor-critical behavior: legal-entity INN(10)/OGRN(13) are business data, NOT 152-ФЗ
// personal data — they are the payload of tender/dealer chat and MUST pass through untouched.
func TestPII_AllowsLegalEntityIdentifiers(t *testing.T) {
	p := plugin(nil)
	in := "поставщик ИНН 7707083893 ОГРН 1027700132195"
	out, sc, err := p.PreLLMHook(nil, chatReq(in))
	if err != nil || sc != nil {
		t.Fatalf("legal-entity IDs must pass, sc=%v err=%v", sc, err)
	}
	if got := *out.ChatRequest.Input[0].Content.ContentStr; got != in {
		t.Errorf("legal-entity IDs must be untouched, got %q", got)
	}
}

// Individual personal data (12-digit INN, phone) is redacted before egress.
func TestPII_RedactsIndividualPII(t *testing.T) {
	p := plugin(nil)
	out, sc, err := p.PreLLMHook(nil, chatReq("мой ИНН 500100732259 тел +7 999 123 45 67"))
	if err != nil || sc != nil {
		t.Fatalf("unexpected block/err: sc=%v err=%v", sc, err)
	}
	if got := *out.ChatRequest.Input[0].Content.ContentStr; got != "мой ИНН <RU_INN> тел <RU_PHONE>" {
		t.Errorf("individual PII not redacted: %q", got)
	}
}

// A random 10-digit number that FAILS the INN checksum is not flagged (checksum is the gate).
func TestPII_ChecksumGate_RandomNumberNotRedacted(t *testing.T) {
	p := plugin(nil)
	out, sc, err := p.PreLLMHook(nil, chatReq("заказ 1234567890 готов"))
	if err != nil || sc != nil {
		t.Fatalf("expected passthrough, sc=%v err=%v", sc, err)
	}
	if got := *out.ChatRequest.Input[0].Content.ContentStr; got != "заказ 1234567890 готов" {
		t.Errorf("random non-INN number should be untouched, got %q", got)
	}
}

// A type configured to "block" refuses the whole request (fail-closed).
func TestPII_BlocksConfiguredEntity(t *testing.T) {
	p := plugin(map[string]string{entityPhone: actionBlock})
	_, sc, _ := p.PreLLMHook(nil, chatReq("тел +7 999 123 45 67"))
	if sc == nil || sc.Error == nil {
		t.Fatal("expected a block for the block-configured entity")
	}
	if sc.Error.Error == nil || sc.Error.Error.Code == nil || *sc.Error.Error.Code != "pii_blocked" {
		t.Errorf("expected code=pii_blocked, got %+v", sc.Error.Error)
	}
}

// Passport is context-gated: no passport context → not flagged; with context → redacted.
func TestPII_Passport_ContextGated(t *testing.T) {
	if _, sc, _ := plugin(nil).PreLLMHook(nil, chatReq("номер 12 34 567890")); sc != nil {
		t.Fatalf("bare number without passport context must not fire, got %+v", sc)
	}
	out, sc, err := plugin(nil).PreLLMHook(nil, chatReq("паспорт серия 12 34 567890"))
	if err != nil || sc != nil {
		t.Fatalf("passport should redact (default), got sc=%v err=%v", sc, err)
	}
	if got := *out.ChatRequest.Input[0].Content.ContentStr; got != "паспорт серия <RU_PASSPORT>" {
		t.Errorf("passport not redacted: %q", got)
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

// The RAG embedding path is redacted, never blocked — even for a block-configured entity, the
// embedding degrades block→redact (a blocked embedding would silently break retrieval).
func TestPII_EmbeddingNeverBlocked(t *testing.T) {
	p := plugin(map[string]string{entityPhone: actionBlock})
	req := &schemas.BifrostRequest{
		EmbeddingRequest: &schemas.BifrostEmbeddingRequest{
			Input: &schemas.EmbeddingInput{Text: schemas.Ptr("контакт +7 999 123 45 67")},
		},
	}
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("embedding must be redacted, not blocked: sc=%v err=%v", sc, err)
	}
	if got := *out.EmbeddingRequest.Input.Text; got != "контакт <RU_PHONE>" {
		t.Errorf("embedding text not redacted: %q", got)
	}
}

func TestPII_RedactsImageGenPrompt(t *testing.T) {
	p := plugin(nil)
	req := &schemas.BifrostRequest{
		ImageGenerationRequest: &schemas.BifrostImageGenerationRequest{
			Input: &schemas.ImageGenerationInput{Prompt: "портрет тел +7 999 123 45 67"},
		},
	}
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("image-gen prompt must be redacted, not blocked: sc=%v err=%v", sc, err)
	}
	if got := out.ImageGenerationRequest.Input.Prompt; got != "портрет тел <RU_PHONE>" {
		t.Errorf("image prompt not redacted: %q", got)
	}
}

// A prompt-bearing shape collectTextSpans doesn't cover must fail closed (block).
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

// #1813: a content-bearing shape the OLD deny-list did NOT enumerate (e.g. file-upload) used to pass
// un-redacted (fail-OPEN). The allow-list must now block it.
func TestPII_BlocksUnenumeratedContentShape(t *testing.T) {
	p := plugin(nil)
	req := &schemas.BifrostRequest{FileUploadRequest: &schemas.BifrostFileUploadRequest{}}
	_, sc, err := p.PreLLMHook(nil, req)
	if err != nil {
		t.Fatalf("must not return a bare error: %v", err)
	}
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || sc.Error.Error.Code == nil ||
		*sc.Error.Error.Code != "pii_unsupported_shape" {
		t.Fatalf("expected a fail-closed block for a previously-unenumerated content shape, got %+v", sc)
	}
}

// #1813: a request with NO recognized shape (a new/unknown Bifrost request type) must fail closed.
func TestPII_BlocksUnknownEmptyShape(t *testing.T) {
	p := plugin(nil)
	_, sc, err := p.PreLLMHook(nil, &schemas.BifrostRequest{})
	if err != nil {
		t.Fatalf("must not return a bare error: %v", err)
	}
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || sc.Error.Error.Code == nil ||
		*sc.Error.Error.Code != "pii_unsupported_shape" {
		t.Fatalf("expected a fail-closed block for an unrecognized shape, got %+v", sc)
	}
}

// #1813: a content-free operational op (no user text egresses) must pass — neither blocked nor a
// redaction attempt.
func TestPII_AllowsContentFreeOp(t *testing.T) {
	p := plugin(nil)
	req := &schemas.BifrostRequest{ListModelsRequest: &schemas.BifrostListModelsRequest{}}
	out, sc, err := p.PreLLMHook(nil, req)
	if err != nil || sc != nil {
		t.Fatalf("content-free op must pass (not block): sc=%v err=%v", sc, err)
	}
	if out == nil {
		t.Fatal("expected the request to pass through unchanged")
	}
}

// A raw request-body passthrough egresses the ORIGINAL bytes span redaction never touches; block it.
func TestPII_BlocksRawPassthrough(t *testing.T) {
	p := plugin(nil)
	bctx := schemas.NewBifrostContextWithValue(context.Background(), time.Time{}, "seed", "x")
	bctx.SetValue(schemas.BifrostContextKeyUseRawRequestBody, true)
	_, sc, err := p.PreLLMHook(bctx, chatReq("мой ИНН 500100732259"))
	if err != nil {
		t.Fatalf("must not return a bare error: %v", err)
	}
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || sc.Error.Error.Code == nil ||
		*sc.Error.Error.Code != "pii_raw_passthrough_unredactable" {
		t.Fatalf("expected a fail-closed block on raw passthrough, got %+v", sc)
	}
}

// actionFor: unknown action value falls back to redact (never silently allow).
func TestActionFor_UnknownFallsBackToRedact(t *testing.T) {
	p := New(Config{Actions: map[string]string{entityPhone: "bogus"}})
	if got := p.actionFor(entityPhone); got != actionRedact {
		t.Errorf("unknown action must fall back to redact, got %q", got)
	}
	if got := p.actionFor("RU_UNLISTED"); got != actionRedact {
		t.Errorf("unlisted type must default to redact, got %q", got)
	}
}
