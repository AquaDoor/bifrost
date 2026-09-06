package aquadoorusermeter

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const svcVK = "sk-bf-service-000"

func newCtx() *schemas.BifrostContext {
	return schemas.NewBifrostContextWithValue(context.Background(), time.Time{}, "seed", "x")
}

func req(headers map[string]string) *schemas.HTTPRequest {
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	return &schemas.HTTPRequest{Headers: h, Query: map[string]string{}, PathParams: map[string]string{}}
}

func userID(ctx *schemas.BifrostContext) string {
	v, _ := ctx.Value(schemas.BifrostContextKeyUserID).(string)
	return v
}

func TestPreHook_Asserter_StampsUserID(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil)
	ctx := newCtx()
	r := req(map[string]string{"Authorization": "Bearer " + svcVK, "X-Aquadoor-User-Email": "user@aquadoor.dev"})
	resp, err := p.HTTPTransportPreHook(ctx, r)
	if resp != nil || err != nil {
		t.Fatalf("expected continue, got resp=%v err=%v", resp, err)
	}
	if got := userID(ctx); got != "user@aquadoor.dev" {
		t.Fatalf("user_id not stamped: %q", got)
	}
	// The credential MUST be unchanged (no swap) — routing stays on the service VK.
	if r.Headers["Authorization"] != "Bearer "+svcVK {
		t.Fatalf("Authorization must be untouched, got %q", r.Headers["Authorization"])
	}
}

func TestPreHook_XbfvkAsserter_StampsUserID(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil)
	ctx := newCtx()
	r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "user@aquadoor.dev"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "user@aquadoor.dev" {
		t.Fatalf("user_id not stamped via x-bf-vk: %q", got)
	}
}

func TestPreHook_NonAsserter_NoStamp(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil)
	ctx := newCtx()
	// A caller presenting some OTHER credential + a spoofed email must NOT be attributed.
	r := req(map[string]string{"Authorization": "Bearer sk-bf-someone-else", "X-Aquadoor-User-Email": "victim@aquadoor.dev"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "" {
		t.Fatalf("must not attribute a non-asserter caller, got %q", got)
	}
}

func TestPreHook_NoEmail_NoStamp(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil)
	ctx := newCtx()
	r := req(map[string]string{"Authorization": "Bearer " + svcVK}) // service job, no user context
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "" {
		t.Fatalf("no email → no attribution, got %q", got)
	}
}

func TestPreHook_B64Email_Decoded(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil)
	ctx := newCtx()
	enc := "b64:" + base64.StdEncoding.EncodeToString([]byte("tëst@aquadoor.dev"))
	r := req(map[string]string{"Authorization": "Bearer " + svcVK, "X-Aquadoor-User-Email": enc})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "tëst@aquadoor.dev" {
		t.Fatalf("b64 email not decoded: %q", got)
	}
}

func TestPreHook_SelfDisabled_NoStamp(t *testing.T) {
	p := New(Config{AsserterVK: ""}, nil) // disabled (asserter unset)
	ctx := newCtx()
	r := req(map[string]string{"Authorization": "Bearer " + svcVK, "X-Aquadoor-User-Email": "user@aquadoor.dev"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "" {
		t.Fatalf("disabled plugin must not stamp, got %q", got)
	}
}

func TestPreHook_LowercaseHeaders(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil)
	ctx := newCtx()
	// HTTP/2 lowercases header names; email must also be lowercased.
	r := req(map[string]string{"authorization": "Bearer " + svcVK, "x-aquadoor-user-email": "User@AquaDoor.DEV"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "user@aquadoor.dev" {
		t.Fatalf("lowercase headers + email not lowercased: %q", got)
	}
}
