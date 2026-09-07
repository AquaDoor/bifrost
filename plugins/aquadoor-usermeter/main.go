// Package aquadoorusermeter is the AquaDoor per-user cost + limits plugin (#1814, spec §1b). LibreChat
// sends the caller's email as a vouched header on its direct-to-Bifrost LLM egress, presenting the
// shared service VK as the trust anchor. This plugin turns that into per-user governance in Bifrost —
// the single source of truth for cost AND limits — in two modes:
//
//   - Attribution-only (Bind=false, the DARK default): stamp the vouched email as the request's
//     Bifrost end-user identity (BifrostContextKeyUserID → logs.user_id, the `user` dimension) and
//     leave the credential untouched. Routing/keys/budget/rate stay on the service VK, so it cannot
//     break a request. Worst case is "cost attributed to the user, still enforced on the shared VK".
//
//   - Bind (Bind=true, flipped at the tested Stage-4 cutover): resolve the vouched email to the user's
//     per-user VK and REWRITE the request's VK header to it, so the whole pipeline — routing, metering,
//     budget, rate — runs on the per-user VK. This is the SSOT path. It FAILS CLOSED: a vouched email
//     whose VK cannot be resolved is refused, never silently downgraded to the shared service VK (that
//     downgrade, on a per-user VK lacking provider access, was the earlier chat-breaking incident; the
//     broker now stamps each per-user VK with an aquadoor-llm provider_config + allow_all_keys, so a
//     resolved VK routes exactly as the service VK does).
//
// Trust: the email is honored ONLY when the caller presents the configured trusted asserter VK (the
// LibreChat service VK — only LibreChat holds it, and bifrost:8080 is overlay-internal), so it is not
// spoofable by an end user. Every other caller (an external MCP client presenting its own per-user VK,
// a direct-VK caller) is a pure no-op, so the MCP path is unaffected. Empty asserter → self-disabled.
//
// The bind mechanism is a header rewrite, not a context write: this hook runs BEFORE the transport
// settles the request identity (ConvertToBifrostContext → SettleIdentity), which re-parses the VK
// header, and BifrostContextKeyVirtualKey is a reserved key on a throwaway sibling context here — so a
// ctx.SetValue would be clobbered. Rewriting req.Headers is applied back onto the request the transport
// then parses, which is the only lever that survives (transports/bifrost-http/handlers/middlewares.go,
// transports/bifrost-http/lib/ctx.go, plugins/governance/store.go PresentedVirtualKey).
package aquadoorusermeter

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// PluginName is the registration name (mirrors aquadoor-pii / aquadoor-obo).
const PluginName = "aquadoor-usermeter"

// DefaultEmailHeader is the header LibreChat stamps with the vouched end-user email.
const DefaultEmailHeader = "X-Aquadoor-User-Email"

// defaultCacheTTL bounds how long a resolved email→VK value is reused before re-resolving. The VK
// value is stable and governance re-reads the VK's live budget/permits by value every request, so a
// cached value cannot over-permit; the cache only saves the by-name store scan on the hot path.
const defaultCacheTTL = 30 * time.Second

// VirtualKeyResolver resolves a per-user Virtual Key by its NAME (the user's lowercased email) to the
// VK VALUE (sk-bf-…) governance binds. `found` is false when the user has no VK — the caller then
// fails closed. `active` reports whether the VK is currently usable; an inactive/expired VK is treated
// as unresolved here (governance would refuse it anyway). The concrete implementation is backed by the
// governance store and wired in the server; tests supply a fake.
type VirtualKeyResolver interface {
	ResolveVKValueByName(ctx context.Context, name string) (value string, active bool, found bool)
}

// Config for the per-user cost + limits plugin.
//   - AsserterVK: the trusted caller's VK value (the LibreChat service VK). The email header is honored
//     ONLY when the request presents THIS credential. SECRET → supplied from env, never config.json.
//     Empty → the plugin self-disables (pure no-op).
//   - EmailHeader defaults to X-Aquadoor-User-Email.
//   - Bind switches from attribution-only (dark) to per-user-VK binding (the SSOT path). Ships false;
//     flipped at the tested Stage-4 cutover. When true the plugin fails CLOSED on an unresolvable VK.
//   - CacheTTL bounds email→VK value reuse. 0 → defaultCacheTTL.
type Config struct {
	AsserterVK  string
	EmailHeader string
	Bind        bool
	CacheTTL    time.Duration
}

// Plugin stamps a LibreChat-vouched end-user email and (when Bind is on) binds the caller's per-user VK.
type Plugin struct {
	asserterVK string
	emailHdr   string
	enabled    bool
	bind       bool
	resolver   VirtualKeyResolver
	cacheTTL   time.Duration
	logger     schemas.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	value   string
	expires time.Time
}

// New builds the plugin. `resolver` may be nil when Bind is off (attribution-only needs none).
// `logger` may be nil.
func New(cfg Config, resolver VirtualKeyResolver, logger schemas.Logger) *Plugin {
	emailHdr := cfg.EmailHeader
	if strings.TrimSpace(emailHdr) == "" {
		emailHdr = DefaultEmailHeader
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	return &Plugin{
		asserterVK: cfg.AsserterVK,
		emailHdr:   emailHdr,
		enabled:    strings.TrimSpace(cfg.AsserterVK) != "",
		bind:       cfg.Bind,
		resolver:   resolver,
		cacheTTL:   ttl,
		logger:     logger,
		cache:      make(map[string]cacheEntry),
	}
}

func (p *Plugin) GetName() string { return PluginName }
func (p *Plugin) Cleanup() error  { return nil }

// HTTPTransportPreHook runs AFTER authentication and BEFORE the handler settles the request identity.
// When the caller presents the trusted asserter VK and vouches an end-user email, it stamps that email
// as the request's end-user identity and, when Bind is on, rewrites the request's VK header to the
// user's per-user VK (fail-closed). Non-asserter callers and asserter calls with no user (system jobs)
// pass through untouched.
func (p *Plugin) HTTPTransportPreHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	if !p.enabled || ctx == nil || req == nil {
		return nil, nil
	}
	// Proof-of-asserter: only act when the caller presents the trusted service VK. Every other caller
	// (external MCP clients presenting their own per-user VK, direct-VK callers) is untouched.
	presented := presentedVKValue(req)
	if presented == "" || presented != p.asserterVK {
		return nil, nil
	}
	email := decodeEmailHeader(req.CaseInsensitiveHeaderLookup(p.emailHdr))
	if email == "" {
		// A service-VK call with no user context (a system job) — attribute to the service VK and route
		// on it as before. Never fail closed here: this is a legitimate non-user call.
		return nil, nil
	}

	// Always stamp the end-user dimension so cost logs carry the user on BOTH paths. BifrostContextKeyUserID
	// is not a reserved key, so this write is honored and crosses the transport boundary via user values.
	ctx.SetValue(schemas.BifrostContextKeyUserID, email)

	if !p.bind {
		// Attribution-only (dark): keep the service VK; do not touch routing.
		if p.logger != nil {
			p.logger.Debug("aquadoor-usermeter: attributed request to user %s (bind off)", email)
		}
		return nil, nil
	}

	// Bind path (SSOT): resolve email → per-user VK VALUE and rewrite the VK header. FAIL CLOSED.
	if p.resolver == nil {
		// Bind requested but no resolver wired — a misconfiguration. Refuse rather than downgrade.
		return refuse(http.StatusInternalServerError, "usermeter_no_resolver",
			"per-user VK binding enabled but no resolver configured"), nil
	}
	vkValue, ok := p.resolve(ctx, email)
	if !ok || vkValue == "" {
		if p.logger != nil {
			p.logger.Warn("aquadoor-usermeter: no active per-user VK for %s — refusing (fail-closed)", email)
		}
		return refuse(http.StatusForbidden, "usermeter_no_vk",
			"no active per-user virtual key for the vouched user"), nil
	}
	rewriteAsserterHeaders(req.Headers, presented, vkValue)
	if p.logger != nil {
		p.logger.Debug("aquadoor-usermeter: bound request to the per-user VK for %s", email)
	}
	return nil, nil
}

// resolve returns the per-user VK value for an email, memoized for cacheTTL. Only positive, active
// resolutions are cached: a just-provisioned (Stage 3) or just-reactivated user must resolve on their
// next request, not after the TTL, so misses and inactive VKs are never cached.
func (p *Plugin) resolve(ctx context.Context, email string) (string, bool) {
	now := time.Now()
	p.mu.Lock()
	if e, ok := p.cache[email]; ok && now.Before(e.expires) {
		v := e.value
		p.mu.Unlock()
		return v, true
	}
	p.mu.Unlock()

	value, active, found := p.resolver.ResolveVKValueByName(ctx, email)
	if !found || value == "" || !active {
		return "", false
	}
	p.mu.Lock()
	p.cache[email] = cacheEntry{value: value, expires: now.Add(p.cacheTTL)}
	p.mu.Unlock()
	return value, true
}

// The remaining HTTP transport hooks are no-ops — everything happens in PreHook (after auth).
func (p *Plugin) HTTPTransportPreAuthHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}
func (p *Plugin) HTTPTransportPostHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest, _ *schemas.HTTPResponse) error {
	return nil
}
func (p *Plugin) HTTPTransportStreamChunkHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest, chunk *schemas.BifrostStreamChunk) (*schemas.BifrostStreamChunk, error) {
	return chunk, nil
}

// rewriteAsserterHeaders replaces the SERVICE (asserter) VK with the per-user VK in EVERY VK-bearing
// header that currently presents it, IN PLACE — preserving each header's key case (headers arrive
// canonical-cased, e.g. "X-Bf-Vk"; a differently-cased write would leave the original for the transport
// to still parse) and its format (Bearer for Authorization, raw otherwise). The transport parses VK
// headers last-wins in no fixed order (transports/bifrost-http/lib/ctx.go), so a second header left on
// the asserter could win — rewriting them all closes that. Only headers carrying the asserter are
// touched, so an unrelated credential is left alone; the caller guarantees presented==asserter, so at
// least one header is rewritten. (Mirrors the audit-hardened pre-#1814-§1a shape it re-enables.)
func rewriteAsserterHeaders(headers map[string]string, asserter, perUserVK string) {
	if headers == nil {
		return
	}
	for k, v := range headers {
		switch strings.ToLower(k) {
		case "x-bf-vk", "x-api-key", "x-goog-api-key", "api-key":
			if strings.TrimSpace(v) == asserter {
				headers[k] = perUserVK
			}
		case "authorization":
			t := strings.TrimSpace(v)
			if len(t) >= 7 && strings.EqualFold(t[:7], "bearer ") && strings.TrimSpace(t[7:]) == asserter {
				headers[k] = "Bearer " + perUserVK
			}
		}
	}
}

// refuse builds a fail-closed short-circuit response. A plain struct (not the pooled AcquireHTTPResponse)
// keeps ownership unambiguous on this rare error path.
func refuse(status int, code, msg string) *schemas.HTTPResponse {
	return &schemas.HTTPResponse{
		StatusCode: status,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(fmt.Sprintf(`{"error":{"type":"usermeter_guardrail","code":%q,"message":%q}}`, code, msg)),
	}
}

// presentedVKValue returns the VK value the request presents — x-bf-vk first, else Authorization:
// Bearer sk-bf-… — mirroring the transport's own recognition. "" if none.
func presentedVKValue(req *schemas.HTTPRequest) string {
	if v := strings.TrimSpace(req.CaseInsensitiveHeaderLookup("x-bf-vk")); v != "" {
		return v
	}
	a := strings.TrimSpace(req.CaseInsensitiveHeaderLookup("authorization"))
	if len(a) >= 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

// decodeEmailHeader unwraps LibreChat's `b64:<base64>` non-ASCII header encoding and lowercases;
// plain ASCII emails pass through untouched. A malformed b64 body is returned as-is (a harmless
// mis-attribution at worst — the attribution path never blocks; the bind path fails closed if the
// resulting string resolves to no VK).
func decodeEmailHeader(s string) string {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, "b64:")
	if !ok {
		return strings.ToLower(s)
	}
	if dec, err := base64.StdEncoding.DecodeString(rest); err == nil {
		return strings.ToLower(strings.TrimSpace(string(dec)))
	}
	if dec, err := base64.RawStdEncoding.DecodeString(rest); err == nil {
		return strings.ToLower(strings.TrimSpace(string(dec)))
	}
	return strings.ToLower(s)
}
