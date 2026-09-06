package aquadoorusermeter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// PluginName is the registration name (mirrors aquadoor-pii / aquadoor-obo).
const PluginName = "aquadoor-usermeter"

// DefaultEmailHeader is the header LibreChat stamps with the vouched end-user email.
const DefaultEmailHeader = "X-Aquadoor-User-Email"

// Config for the per-user metering plugin.
//
//   - AsserterVK is the trusted caller's VK value (the LibreChat service VK, sk-bf-…). The email
//     header is honored ONLY when the request presents THIS credential — proof that LibreChat (the
//     only holder of that secret, reachable only on the internal overlay) is vouching for the
//     end-user. It is a SECRET → supplied from env, never config.json. EMPTY → the plugin
//     self-disables (pure pass-through), so the fork can ship it dark and enable it at cutover.
//   - EmailHeader defaults to X-Aquadoor-User-Email.
//   - CacheTTLSeconds is the email→VK resolver cache TTL (default 60s).
type Config struct {
	AsserterVK      string
	EmailHeader     string
	CacheTTLSeconds int
}

// Plugin resolves a LibreChat-vouched end-user email to that user's Bifrost VK and rewrites the
// presented credential in HTTPTransportPreAuthHook, so governance meters cost/budget/rate per user.
type Plugin struct {
	asserterVK string
	emailHdr   string
	enabled    bool
	resolver   *Resolver
	logger     schemas.Logger
}

// New builds the plugin. `store` supplies email→VK resolution (the config store); `logger` may be nil.
func New(cfg Config, store VKStore, logger schemas.Logger) *Plugin {
	emailHdr := cfg.EmailHeader
	if strings.TrimSpace(emailHdr) == "" {
		emailHdr = DefaultEmailHeader
	}
	ttl := time.Duration(cfg.CacheTTLSeconds) * time.Second
	return &Plugin{
		asserterVK: cfg.AsserterVK,
		emailHdr:   emailHdr,
		enabled:    strings.TrimSpace(cfg.AsserterVK) != "" && store != nil,
		resolver:   NewResolver(store, ttl),
		logger:     logger,
	}
}

func (p *Plugin) GetName() string { return PluginName }
func (p *Plugin) Cleanup() error  { return nil }

// HTTPTransportPreAuthHook is the credential-deriving hook (the interface's blessed pattern). It runs
// before authentication settles the identity, so rewriting the presented VK here is what governance
// meters. Returns (nil,nil) to continue (with any header mutation applied), or a populated
// *HTTPResponse to short-circuit fail-closed.
func (p *Plugin) HTTPTransportPreAuthHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	if !p.enabled || req == nil {
		return nil, nil // self-disabled (asserter unset) → normal VK auth for everyone
	}

	// 1. Proof-of-asserter: honor the vouched email ONLY when the caller presents the trusted VK.
	presented, headerKey, bearer := presentedCredential(req)
	if presented == "" || presented != p.asserterVK {
		return nil, nil // not LibreChat vouching — leave the request's own credential untouched
	}

	// 2. The vouched end-user. Absent → a service-VK call with no user context (system job) →
	//    meter against the service VK as before.
	emailRaw := req.CaseInsensitiveHeaderLookup(p.emailHdr)
	if strings.TrimSpace(emailRaw) == "" {
		return nil, nil
	}
	email := decodeEmailHeader(emailRaw)

	// 3. Resolve email → the user's per-user VK value.
	vkValue, found, err := p.resolver.ResolveVKValue(ctx, email)
	if err != nil {
		// Transient store failure — FAIL CLOSED (never silently meter to the shared service VK).
		if p.logger != nil {
			p.logger.Error("aquadoor-usermeter: VK resolve failed for %s: %v (blocking, fail-closed)", email, err)
		}
		return blockResponse(503, "vk_resolve_error", "could not resolve the per-user virtual key"), nil
	}
	if !found {
		// No VK for this user. Provision-at-login (broker) should have created it, so this is a real
		// defect — surface it LOUDLY and FAIL CLOSED rather than mis-attributing cost to the service VK.
		if p.logger != nil {
			p.logger.Warn("aquadoor-usermeter: no per-user VK for %s — is provision-at-login wired + does the user hold baseline caps? (blocking, fail-closed)", email)
		}
		return blockResponse(403, "no_per_user_vk", "no per-user virtual key is provisioned for this user"), nil
	}

	// 4. Swap the presented credential to the per-user VK, so identity settles on it and governance
	//    meters this user. Rewrite the SAME header the asserter arrived on (deterministic — avoids the
	//    x-bf-vk-vs-Authorization precedence question).
	newCred := vkValue
	if bearer {
		newCred = "Bearer " + vkValue
	}
	setHeaderValue(req.Headers, headerKey, newCred)
	if p.logger != nil {
		p.logger.Debug("aquadoor-usermeter: metering request per-user (email=%s)", email)
	}
	return nil, nil
}

// The remaining HTTP transport hooks are no-ops — this plugin only derives the credential pre-auth.
func (p *Plugin) HTTPTransportPreHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}
func (p *Plugin) HTTPTransportPostHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest, _ *schemas.HTTPResponse) error {
	return nil
}
func (p *Plugin) HTTPTransportStreamChunkHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest, chunk *schemas.BifrostStreamChunk) (*schemas.BifrostStreamChunk, error) {
	return chunk, nil
}

// presentedCredential returns the VK value the request presents, the header it arrived on, and
// whether that header is Bearer-wrapped — mirroring the transport's own recognition order
// (x-bf-vk, then Authorization: Bearer sk-bf-…). headerKey is a lowercase canonical name;
// setHeaderValue matches the real header case-insensitively when rewriting.
func presentedCredential(req *schemas.HTTPRequest) (value, headerKey string, bearer bool) {
	if v := strings.TrimSpace(req.CaseInsensitiveHeaderLookup("x-bf-vk")); v != "" {
		return v, "x-bf-vk", false
	}
	a := strings.TrimSpace(req.CaseInsensitiveHeaderLookup("authorization"))
	if len(a) >= 7 && strings.EqualFold(a[:7], "bearer ") {
		if t := strings.TrimSpace(a[7:]); t != "" {
			return t, "authorization", true
		}
	}
	return "", "", false
}

// setHeaderValue overwrites the value of an existing header (matched case-insensitively, preserving
// its original key case so no duplicate key is introduced), or sets canonicalKey when absent.
func setHeaderValue(headers map[string]string, canonicalKey, value string) {
	if headers == nil {
		return
	}
	for k := range headers {
		if strings.EqualFold(k, canonicalKey) {
			headers[k] = value
			return
		}
	}
	headers[canonicalKey] = value
}

// decodeEmailHeader unwraps LibreChat's `b64:<base64>` non-ASCII header encoding. Plain ASCII emails
// (the corporate-SSO norm) pass through untouched. A malformed b64 body is returned as-is (the
// resolver then misses → fail-closed), never silently accepted as some other value.
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

func blockResponse(status int, code, detail string) *schemas.HTTPResponse {
	body, _ := json.Marshal(map[string]string{"error": code, "detail": detail})
	return &schemas.HTTPResponse{
		StatusCode: status,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       body,
	}
}
