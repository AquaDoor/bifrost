package aquadoorusermeter

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
)

func storeWith(pairs map[string]string) *fakeStore {
	s := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{}}
	for name, val := range pairs {
		s.vks[name] = vk(name, val)
	}
	return s
}

func req(headers map[string]string) *schemas.HTTPRequest {
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	return &schemas.HTTPRequest{Headers: h, Query: map[string]string{}, PathParams: map[string]string{}}
}

const svcVK = "sk-bf-service-000"

func TestPreAuth_Asserter_RewritesAuthorizationToPerUserVK(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{"user@aquadoor.dev": "sk-bf-user-123"}), nil)
	r := req(map[string]string{
		"Authorization":         "Bearer " + svcVK,
		"X-Aquadoor-User-Email": "user@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("expected continue (nil,nil), got resp=%v err=%v", resp, err)
	}
	if got := r.Headers["Authorization"]; got != "Bearer sk-bf-user-123" {
		t.Fatalf("Authorization not swapped to per-user VK: %q", got)
	}
}

func TestPreAuth_Asserter_ViaXbfvk_RewritesRaw(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{"user@aquadoor.dev": "sk-bf-user-123"}), nil)
	r := req(map[string]string{
		"x-bf-vk":               svcVK,
		"X-Aquadoor-User-Email": "user@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("expected continue, got resp=%v err=%v", resp, err)
	}
	if got := r.Headers["x-bf-vk"]; got != "sk-bf-user-123" {
		t.Fatalf("x-bf-vk not swapped (raw, no Bearer): %q", got)
	}
}

func TestPreAuth_NonAsserterCredential_LeftUntouched(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{"user@aquadoor.dev": "sk-bf-user-123"}), nil)
	// A caller presenting some OTHER VK + a (spoofed) email must NOT be re-attributed.
	r := req(map[string]string{
		"Authorization":         "Bearer sk-bf-someone-elses-key",
		"X-Aquadoor-User-Email": "victim@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("expected pass-through, got resp=%v err=%v", resp, err)
	}
	if got := r.Headers["Authorization"]; got != "Bearer sk-bf-someone-elses-key" {
		t.Fatalf("non-asserter credential must be untouched, got %q", got)
	}
}

func TestPreAuth_Asserter_NoEmail_MetersServiceVK(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{}), nil)
	r := req(map[string]string{"Authorization": "Bearer " + svcVK}) // service job, no user context
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("expected pass-through, got resp=%v err=%v", resp, err)
	}
	if got := r.Headers["Authorization"]; got != "Bearer "+svcVK {
		t.Fatalf("service VK must be untouched when no email, got %q", got)
	}
}

func TestPreAuth_B64Email_Decoded(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{"tëst@aquadoor.dev": "sk-bf-unicode"}), nil)
	enc := "b64:" + base64.StdEncoding.EncodeToString([]byte("tëst@aquadoor.dev"))
	r := req(map[string]string{
		"Authorization":         "Bearer " + svcVK,
		"X-Aquadoor-User-Email": enc,
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("expected continue, got resp=%v err=%v", resp, err)
	}
	if got := r.Headers["Authorization"]; got != "Bearer sk-bf-unicode" {
		t.Fatalf("b64 email not decoded+resolved: %q", got)
	}
}

func TestPreAuth_Asserter_UnresolvedEmail_FailsClosed403(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{}), nil) // no VK for the email
	r := req(map[string]string{
		"Authorization":         "Bearer " + svcVK,
		"X-Aquadoor-User-Email": "ghost@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if err != nil {
		t.Fatalf("unexpected err %v", err)
	}
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("expected 403 fail-closed, got %v", resp)
	}
	// MUST NOT fall through to the service VK (no silent mis-attribution).
	if got := r.Headers["Authorization"]; got != "Bearer "+svcVK {
		t.Fatalf("credential must be untouched on fail-closed, got %q", got)
	}
}

func TestPreAuth_Asserter_StoreError_FailsClosed503(t *testing.T) {
	store := &fakeStore{err: errors.New("db down")}
	p := New(Config{AsserterVK: svcVK}, store, nil)
	r := req(map[string]string{
		"Authorization":         "Bearer " + svcVK,
		"X-Aquadoor-User-Email": "user@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if err != nil {
		t.Fatalf("unexpected err %v", err)
	}
	if resp == nil || resp.StatusCode != 503 {
		t.Fatalf("expected 503 fail-closed, got %v", resp)
	}
}

func TestPreAuth_SelfDisabled_WhenAsserterUnset(t *testing.T) {
	// AsserterVK empty → plugin disabled → pure pass-through even with an email present.
	p := New(Config{AsserterVK: ""}, storeWith(map[string]string{"user@aquadoor.dev": "sk-bf-user"}), nil)
	r := req(map[string]string{
		"Authorization":         "Bearer " + svcVK,
		"X-Aquadoor-User-Email": "user@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("disabled plugin must pass through, got resp=%v err=%v", resp, err)
	}
	if got := r.Headers["Authorization"]; got != "Bearer "+svcVK {
		t.Fatalf("disabled plugin must not rewrite, got %q", got)
	}
}

func TestPreAuth_DoubleAsserterHeaders_BothRewritten(t *testing.T) {
	// Defensive (M3): if the asserter is presented in BOTH x-bf-vk and Authorization, both must be
	// swapped to the per-user VK — leaving either on the asserter could let the transport (last-wins
	// over all VK headers) re-settle the shared service VK.
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{"user@aquadoor.dev": "sk-bf-user-123"}), nil)
	r := req(map[string]string{
		"x-bf-vk":               svcVK,
		"Authorization":         "Bearer " + svcVK,
		"X-Aquadoor-User-Email": "user@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("expected continue, got resp=%v err=%v", resp, err)
	}
	if r.Headers["x-bf-vk"] != "sk-bf-user-123" {
		t.Fatalf("x-bf-vk not swapped: %q", r.Headers["x-bf-vk"])
	}
	if r.Headers["Authorization"] != "Bearer sk-bf-user-123" {
		t.Fatalf("Authorization not swapped: %q — leaves the service VK settleable", r.Headers["Authorization"])
	}
}

func TestPreAuth_LowercaseAuthorizationHeader_RewrittenInPlace(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, storeWith(map[string]string{"user@aquadoor.dev": "sk-bf-user-123"}), nil)
	// HTTP/2 clients lowercase header names.
	r := req(map[string]string{
		"authorization":         "Bearer " + svcVK,
		"x-aquadoor-user-email": "user@aquadoor.dev",
	})
	resp, err := p.HTTPTransportPreAuthHook(&schemas.BifrostContext{}, r)
	if resp != nil || err != nil {
		t.Fatalf("expected continue, got resp=%v err=%v", resp, err)
	}
	if got := r.Headers["authorization"]; got != "Bearer sk-bf-user-123" {
		t.Fatalf("lowercase authorization not rewritten in place: %q", got)
	}
	// No duplicate canonical-case key introduced.
	if _, dup := r.Headers["Authorization"]; dup {
		t.Fatalf("must not introduce a duplicate Authorization key")
	}
}
