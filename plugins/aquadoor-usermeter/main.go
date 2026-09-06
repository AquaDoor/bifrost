// Package aquadoorusermeter is the AquaDoor per-user cost-attribution plugin (#1814). LibreChat sends
// the caller's email as a vouched header on its direct-to-Bifrost LLM egress; this plugin stamps that
// email as the request's Bifrost end-user identity (BifrostContextKeyUserID) so the logging plugin
// records cost PER USER (Bifrost's `user` dimension). The request KEEPS the shared service VK — the
// plugin never swaps the credential, so it cannot affect LLM routing, keys, budget or rate. Worst
// case is "cost unattributed for one request", never a broken request. (Per-user *limits* are
// enforced by LibreChat's native Balance, not by a per-user VK — Bifrost per-VK routing made per-user
// VKs impractical for the LLM path; see #1814.)
//
// Trust: the email is honored ONLY when the caller presents the configured trusted asserter VK (the
// LibreChat service VK — only LibreChat holds it, and bifrost:8080 is overlay-internal), so the
// header is not spoofable by an end user. Empty asserter → self-disabled (pure no-op).
package aquadoorusermeter

import (
	"encoding/base64"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// PluginName is the registration name (mirrors aquadoor-pii / aquadoor-obo).
const PluginName = "aquadoor-usermeter"

// DefaultEmailHeader is the header LibreChat stamps with the vouched end-user email.
const DefaultEmailHeader = "X-Aquadoor-User-Email"

// Config for the per-user attribution plugin.
//   - AsserterVK: the trusted caller's VK value (the LibreChat service VK). The email header is
//     honored ONLY when the request presents THIS credential. SECRET → supplied from env, never
//     config.json. Empty → the plugin self-disables (pure no-op), so it ships dark until cutover.
//   - EmailHeader defaults to X-Aquadoor-User-Email.
type Config struct {
	AsserterVK  string
	EmailHeader string
}

// Plugin stamps a LibreChat-vouched end-user email onto the request as its Bifrost user identity.
type Plugin struct {
	asserterVK string
	emailHdr   string
	enabled    bool
	logger     schemas.Logger
}

// New builds the plugin. `logger` may be nil.
func New(cfg Config, logger schemas.Logger) *Plugin {
	emailHdr := cfg.EmailHeader
	if strings.TrimSpace(emailHdr) == "" {
		emailHdr = DefaultEmailHeader
	}
	return &Plugin{
		asserterVK: cfg.AsserterVK,
		emailHdr:   emailHdr,
		enabled:    strings.TrimSpace(cfg.AsserterVK) != "",
		logger:     logger,
	}
}

func (p *Plugin) GetName() string { return PluginName }
func (p *Plugin) Cleanup() error  { return nil }

// HTTPTransportPreHook runs AFTER authentication settles the identity and BEFORE governance. When the
// caller presents the trusted asserter VK and vouches an end-user email, stamp that email as the
// request's end-user identity (BifrostContextKeyUserID, which the logging plugin records as
// logs.user_id → the `user` dimension). The presented credential (the service VK) is left untouched,
// so routing / keys / budget / rate are unchanged — this is attribution ONLY and can never break a
// request. BifrostContextKeyUserID is not a reserved key, so this write is honored.
func (p *Plugin) HTTPTransportPreHook(ctx *schemas.BifrostContext, req *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	if !p.enabled || ctx == nil || req == nil {
		return nil, nil
	}
	// Proof-of-asserter: only honor the vouched email when the caller presents the trusted service VK.
	if presented := presentedVKValue(req); presented == "" || presented != p.asserterVK {
		return nil, nil
	}
	email := decodeEmailHeader(req.CaseInsensitiveHeaderLookup(p.emailHdr))
	if email == "" {
		return nil, nil // a service-VK call with no user context (a system job) — attribute to the service VK
	}
	ctx.SetValue(schemas.BifrostContextKeyUserID, email)
	if p.logger != nil {
		p.logger.Debug("aquadoor-usermeter: attributed request to user %s", email)
	}
	return nil, nil
}

// The remaining HTTP transport hooks are no-ops — attribution happens in PreHook (after auth).
func (p *Plugin) HTTPTransportPreAuthHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest) (*schemas.HTTPResponse, error) {
	return nil, nil
}
func (p *Plugin) HTTPTransportPostHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest, _ *schemas.HTTPResponse) error {
	return nil
}
func (p *Plugin) HTTPTransportStreamChunkHook(_ *schemas.BifrostContext, _ *schemas.HTTPRequest, chunk *schemas.BifrostStreamChunk) (*schemas.BifrostStreamChunk, error) {
	return chunk, nil
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
// mis-attribution at worst — this plugin never blocks).
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
