package aquadoorusermeter

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	svcVK  = "sk-bf-service-000"
	userVK = "sk-bf-user-alice-111"
)

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

// fakeResolver stands in for the governance-store-backed VirtualKeyResolver.
type fakeResolver struct {
	mu     sync.Mutex
	byName map[string]fakeVK
	calls  int
}
type fakeVK struct {
	value  string
	active bool
}

func (f *fakeResolver) ResolveVKValueByName(_ context.Context, name string) (string, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	e, ok := f.byName[name]
	if !ok {
		return "", false, false
	}
	return e.value, e.active, true
}

func callCount(f *fakeResolver) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// --- attribution-only (Bind off, the dark default): stamp the user, keep the service VK -------------

func TestPreHook_Asserter_StampsUserID(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil, nil)
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
	p := New(Config{AsserterVK: svcVK}, nil, nil)
	ctx := newCtx()
	r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "user@aquadoor.dev"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "user@aquadoor.dev" {
		t.Fatalf("user_id not stamped via x-bf-vk: %q", got)
	}
	if r.Headers["x-bf-vk"] != svcVK {
		t.Fatalf("x-bf-vk must be untouched when bind is off, got %q", r.Headers["x-bf-vk"])
	}
}

func TestPreHook_NonAsserter_NoStamp(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil, nil)
	ctx := newCtx()
	// A caller presenting some OTHER credential + a spoofed email must NOT be attributed.
	r := req(map[string]string{"Authorization": "Bearer sk-bf-someone-else", "X-Aquadoor-User-Email": "victim@aquadoor.dev"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "" {
		t.Fatalf("must not attribute a non-asserter caller, got %q", got)
	}
}

func TestPreHook_NoEmail_NoStamp(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil, nil)
	ctx := newCtx()
	r := req(map[string]string{"Authorization": "Bearer " + svcVK}) // service job, no user context
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "" {
		t.Fatalf("no email → no attribution, got %q", got)
	}
}

func TestPreHook_B64Email_Decoded(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil, nil)
	ctx := newCtx()
	enc := "b64:" + base64.StdEncoding.EncodeToString([]byte("tëst@aquadoor.dev"))
	r := req(map[string]string{"Authorization": "Bearer " + svcVK, "X-Aquadoor-User-Email": enc})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "tëst@aquadoor.dev" {
		t.Fatalf("b64 email not decoded: %q", got)
	}
}

func TestPreHook_SelfDisabled_NoStamp(t *testing.T) {
	p := New(Config{AsserterVK: ""}, nil, nil) // disabled (asserter unset)
	ctx := newCtx()
	r := req(map[string]string{"Authorization": "Bearer " + svcVK, "X-Aquadoor-User-Email": "user@aquadoor.dev"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "" {
		t.Fatalf("disabled plugin must not stamp, got %q", got)
	}
}

func TestPreHook_LowercaseHeaders(t *testing.T) {
	p := New(Config{AsserterVK: svcVK}, nil, nil)
	ctx := newCtx()
	// HTTP/2 lowercases header names; email must also be lowercased.
	r := req(map[string]string{"authorization": "Bearer " + svcVK, "x-aquadoor-user-email": "User@AquaDoor.DEV"})
	_, _ = p.HTTPTransportPreHook(ctx, r)
	if got := userID(ctx); got != "user@aquadoor.dev" {
		t.Fatalf("lowercase headers + email not lowercased: %q", got)
	}
}

// --- bind (Bind on, SSOT): resolve email→per-user VK and rewrite the VK header, fail-closed ---------

func bindPlugin(res VirtualKeyResolver) *Plugin {
	return New(Config{AsserterVK: svcVK, Bind: true}, res, nil)
}

func TestBind_RewritesXbfvkToPerUserVK(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"alice@aquadoor.dev": {userVK, true}}}
	p := bindPlugin(res)
	ctx := newCtx()
	r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	resp, err := p.HTTPTransportPreHook(ctx, r)
	if resp != nil || err != nil {
		t.Fatalf("expected continue (bound), got resp=%v err=%v", resp, err)
	}
	if r.Headers["x-bf-vk"] != userVK {
		t.Fatalf("x-bf-vk must be rewritten to the per-user VK, got %q", r.Headers["x-bf-vk"])
	}
	if got := userID(ctx); got != "alice@aquadoor.dev" {
		t.Fatalf("user dimension must still be stamped, got %q", got)
	}
}

func TestBind_Unresolved_FailsClosed_NoDowngrade(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{}} // no VK for anyone
	p := bindPlugin(res)
	ctx := newCtx()
	r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "ghost@aquadoor.dev"})
	resp, err := p.HTTPTransportPreHook(ctx, r)
	if err != nil {
		t.Fatalf("fail-closed uses a response, not an error: %v", err)
	}
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("expected 403 refusal, got %v", resp)
	}
	if !strings.Contains(string(resp.Body), "usermeter_no_vk") {
		t.Fatalf("refusal body should name the guardrail, got %q", string(resp.Body))
	}
	// Critical: it must NOT have downgraded/partially-bound — the header is left as-is (the request is
	// refused, never routed on a fallback).
	if r.Headers["x-bf-vk"] != svcVK {
		t.Fatalf("must not rewrite the header when failing closed, got %q", r.Headers["x-bf-vk"])
	}
}

func TestBind_InactiveVK_FailsClosed(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"alice@aquadoor.dev": {userVK, false}}} // found but inactive
	p := bindPlugin(res)
	ctx := newCtx()
	r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	resp, _ := p.HTTPTransportPreHook(ctx, r)
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("inactive VK must fail closed with 403, got %v", resp)
	}
	if r.Headers["x-bf-vk"] != svcVK {
		t.Fatalf("must not bind an inactive VK, got %q", r.Headers["x-bf-vk"])
	}
}

func TestBind_NilResolver_ServerError(t *testing.T) {
	p := New(Config{AsserterVK: svcVK, Bind: true}, nil, nil) // bind on but no resolver wired
	ctx := newCtx()
	r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	resp, _ := p.HTTPTransportPreHook(ctx, r)
	if resp == nil || resp.StatusCode != 500 {
		t.Fatalf("bind without a resolver must refuse 500, got %v", resp)
	}
	if !strings.Contains(string(resp.Body), "usermeter_no_resolver") {
		t.Fatalf("refusal body should name the misconfiguration, got %q", string(resp.Body))
	}
}

func TestBind_NonAsserter_NoOp(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"alice@aquadoor.dev": {userVK, true}}}
	p := bindPlugin(res)
	ctx := newCtx()
	// An external MCP client presenting its OWN per-user VK must be untouched (MCP path unaffected).
	r := req(map[string]string{"x-bf-vk": "sk-bf-external-client", "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	resp, err := p.HTTPTransportPreHook(ctx, r)
	if resp != nil || err != nil {
		t.Fatalf("non-asserter must be a pure no-op, got resp=%v err=%v", resp, err)
	}
	if r.Headers["x-bf-vk"] != "sk-bf-external-client" {
		t.Fatalf("non-asserter header must be untouched, got %q", r.Headers["x-bf-vk"])
	}
	if callCount(res) != 0 {
		t.Fatalf("non-asserter must not consult the resolver, calls=%d", callCount(res))
	}
	if got := userID(ctx); got != "" {
		t.Fatalf("non-asserter must not be attributed, got %q", got)
	}
}

func TestBind_AsserterNoEmail_NoOp(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{}}
	p := bindPlugin(res)
	ctx := newCtx()
	r := req(map[string]string{"x-bf-vk": svcVK}) // system job, no user
	resp, err := p.HTTPTransportPreHook(ctx, r)
	if resp != nil || err != nil {
		t.Fatalf("asserter-with-no-email must pass through (system job), got resp=%v err=%v", resp, err)
	}
	if callCount(res) != 0 {
		t.Fatalf("no-email must not consult the resolver, calls=%d", callCount(res))
	}
	if r.Headers["x-bf-vk"] != svcVK {
		t.Fatalf("no-email must keep the service VK, got %q", r.Headers["x-bf-vk"])
	}
}

func TestBind_B64Email_ResolvesDecoded(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"tëst@aquadoor.dev": {userVK, true}}}
	p := bindPlugin(res)
	ctx := newCtx()
	enc := "b64:" + base64.StdEncoding.EncodeToString([]byte("Tëst@AquaDoor.DEV"))
	r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": enc})
	resp, _ := p.HTTPTransportPreHook(ctx, r)
	if resp != nil {
		t.Fatalf("expected bind for a resolvable decoded email, got refusal %v", resp)
	}
	if r.Headers["x-bf-vk"] != userVK {
		t.Fatalf("decoded+lowercased email must resolve+bind, got %q", r.Headers["x-bf-vk"])
	}
}

// The service VK can arrive on Authorization: Bearer with no x-bf-vk. After bind, the header that
// carried it must carry the per-user VK (Bearer form preserved) and no header may still carry the
// service VK (the transport parses VK headers unordered, last-wins).
func TestBind_AuthorizationBearer_Neutralized(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"alice@aquadoor.dev": {userVK, true}}}
	p := bindPlugin(res)
	ctx := newCtx()
	r := req(map[string]string{"Authorization": "Bearer " + svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	resp, _ := p.HTTPTransportPreHook(ctx, r)
	if resp != nil {
		t.Fatalf("expected bind, got refusal %v", resp)
	}
	if r.Headers["Authorization"] != "Bearer "+userVK {
		t.Fatalf("Authorization must carry the per-user VK (Bearer form), got %q", r.Headers["Authorization"])
	}
	for k, v := range r.Headers {
		if strings.Contains(v, svcVK) {
			t.Fatalf("no header may still carry the service VK after bind: %s=%q", k, v)
		}
	}
}

// An unrelated (non-asserter) credential on a second VK header must be left untouched — only the
// asserter is rewritten.
func TestBind_LeavesUnrelatedCredentialAlone(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"alice@aquadoor.dev": {userVK, true}}}
	p := bindPlugin(res)
	ctx := newCtx()
	// Asserter on x-bf-vk (what presentedVKValue picks); an unrelated api-key present too.
	r := req(map[string]string{"x-bf-vk": svcVK, "x-api-key": "sk-unrelated", "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	if resp, _ := p.HTTPTransportPreHook(ctx, r); resp != nil {
		t.Fatalf("expected bind, got refusal %v", resp)
	}
	if r.Headers["x-bf-vk"] != userVK {
		t.Fatalf("asserter header must be rewritten, got %q", r.Headers["x-bf-vk"])
	}
	if r.Headers["x-api-key"] != "sk-unrelated" {
		t.Fatalf("unrelated credential must be left untouched, got %q", r.Headers["x-api-key"])
	}
}

// Headers arrive canonical-cased; the rewrite must be IN PLACE, never a lowercase duplicate the
// transport could still parse the old value from.
func TestBind_CanonicalCasedHeader_InPlace(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"alice@aquadoor.dev": {userVK, true}}}
	p := bindPlugin(res)
	ctx := newCtx()
	r := req(map[string]string{"X-Bf-Vk": svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	resp, _ := p.HTTPTransportPreHook(ctx, r)
	if resp != nil {
		t.Fatalf("expected bind, got refusal %v", resp)
	}
	if r.Headers["X-Bf-Vk"] != userVK {
		t.Fatalf("canonical X-Bf-Vk must be rewritten in place, got %q", r.Headers["X-Bf-Vk"])
	}
	if _, dup := r.Headers["x-bf-vk"]; dup {
		t.Fatalf("must not create a lowercase duplicate x-bf-vk alongside X-Bf-Vk")
	}
}

// A resolved email→VK value is memoized for CacheTTL, then re-resolved.
func TestResolve_CacheTTL(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{"alice@aquadoor.dev": {userVK, true}}}
	p := New(Config{AsserterVK: svcVK, Bind: true, CacheTTL: 40 * time.Millisecond}, res, nil)

	call := func() {
		ctx := newCtx()
		r := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
		if resp, _ := p.HTTPTransportPreHook(ctx, r); resp != nil {
			t.Fatalf("unexpected refusal %v", resp)
		}
	}

	call()
	call()
	if got := callCount(res); got != 1 {
		t.Fatalf("second call within TTL must hit cache (calls=1), got %d", got)
	}
	time.Sleep(60 * time.Millisecond)
	call()
	if got := callCount(res); got != 2 {
		t.Fatalf("call after TTL must re-resolve (calls=2), got %d", got)
	}
}

// A miss is NOT cached: a user who gets provisioned between requests must resolve on the next one.
func TestResolve_NegativeNotCached(t *testing.T) {
	res := &fakeResolver{byName: map[string]fakeVK{}}
	p := New(Config{AsserterVK: svcVK, Bind: true, CacheTTL: time.Hour}, res, nil)

	ctx1 := newCtx()
	r1 := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	if resp, _ := p.HTTPTransportPreHook(ctx1, r1); resp == nil || resp.StatusCode != 403 {
		t.Fatalf("expected 403 before provisioning, got %v", resp)
	}
	// Now the user is provisioned.
	res.mu.Lock()
	res.byName["alice@aquadoor.dev"] = fakeVK{userVK, true}
	res.mu.Unlock()

	ctx2 := newCtx()
	r2 := req(map[string]string{"x-bf-vk": svcVK, "X-Aquadoor-User-Email": "alice@aquadoor.dev"})
	if resp, _ := p.HTTPTransportPreHook(ctx2, r2); resp != nil {
		t.Fatalf("must resolve on the next request after provisioning, got refusal %v", resp)
	}
	if r2.Headers["x-bf-vk"] != userVK {
		t.Fatalf("expected bind after provisioning, got %q", r2.Headers["x-bf-vk"])
	}
}
