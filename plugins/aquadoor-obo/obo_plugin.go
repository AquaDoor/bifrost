package aquadoorobo

import (
	"context"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// obo_plugin.go — the Bifrost MCPPlugin adapter around the OBO engine (Service). Before any MCP
// call to a first-party runner client, it resolves the acting user (from the caller's virtual
// key), mints a runner-trusted per-user token (RFC-8693), and injects it as the runner
// Authorization header via BifrostContextKeyMCPExtraHeaders. Fail-closed: no VK, unresolved
// user, or a mint failure returns an MCPPluginShortCircuit (the runner call is refused, never
// sent with the wrong / a capless identity). This carries the acting user as a VERIFIED identity
// (the VK→user mapping owned by the broker), replacing CF's spoofable X-Aquadoor-Act-Email header
// (#1777).

// EmailResolver maps a caller's virtual-key value to the acting user's email. The default
// implementation reads the VK's name (which the broker bridge sets to the user's email); it is an
// interface so it can be cached / swapped / mocked.
type EmailResolver interface {
	EmailForVK(ctx context.Context, vkValue string) (string, error)
}

// OboPlugin injects per-user OBO tokens on runner MCP calls.
type OboPlugin struct {
	svc           *Service
	runnerClients map[string]bool
	resolver      EmailResolver
	logger        schemas.Logger // may be nil (the per-mint audit line is then skipped)
}

var (
	_ schemas.MCPPlugin           = (*OboPlugin)(nil)
	_ schemas.MCPConnectionPlugin = (*OboPlugin)(nil)
)

// NewPlugin builds the adapter. runnerClients are the Bifrost MCP client names that federate the
// AquaDoor runners (only these get an OBO token; Outline/etc. keep their own static auth). logger
// may be nil (the per-mint audit line — spec #1780 §7.8 — is then skipped).
func NewPlugin(svc *Service, runnerClients []string, resolver EmailResolver, logger schemas.Logger) *OboPlugin {
	set := make(map[string]bool, len(runnerClients))
	for _, c := range runnerClients {
		if c != "" {
			set[c] = true
		}
	}
	return &OboPlugin{svc: svc, runnerClients: set, resolver: resolver, logger: logger}
}

func (p *OboPlugin) GetName() string { return "aquadoor-obo" }
func (p *OboPlugin) Cleanup() error  { return nil }

func (p *OboPlugin) PreMCPHook(
	ctx *schemas.BifrostContext,
	req *schemas.BifrostMCPRequest,
) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if req == nil || !p.runnerClients[req.ClientName] {
		return req, nil, nil // not a runner client → untouched (its own static auth applies)
	}
	vk := bifrost.GetStringFromContext(ctx, schemas.BifrostContextKeyVirtualKey)
	if vk == "" {
		return req, blockMCP("obo_no_identity", "no virtual key on a runner MCP call"), nil
	}
	email, err := p.resolver.EmailForVK(ctx, vk)
	if err != nil || email == "" {
		return req, blockMCP("obo_no_identity", "cannot resolve the acting user for OBO"), nil
	}
	token, audit, err := p.svc.GetRunnerToken(ctx, email, "")
	if err != nil {
		return req, blockMCP("obo_mint_failed", "OBO token mint failed: "+err.Error()), nil
	}
	injectMCPHeader(ctx, "Authorization", "Bearer "+token)
	// Audit line (spec #1780 §7.8): one record per runner-token mint, so an OBO grant is traceable
	// to the acting user + resolved Zitadel id (never the spoofable header path #1777 replaced).
	if p.logger != nil {
		p.logger.Info("[aquadoor-obo] runner token minted: client=%s email=%s userId=%s strategy=%s cacheHit=%v",
			req.ClientName, audit.Email, audit.UserID, audit.Strategy, audit.CacheHit)
	}
	return req, nil, nil
}

func (p *OboPlugin) PostMCPHook(
	_ *schemas.BifrostContext,
	resp *schemas.BifrostMCPResponse,
	bifrostErr *schemas.BifrostError,
) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}

// PreMCPConnectionHook injects a machine ACTOR token (scoped to the runner audience) as the
// Authorization header on the runner MCP CONNECTION, so Bifrost can discover the runner's tool
// catalog — the runner's tools/list serves the full catalog to any authenticated caller; per-user
// enforcement happens on tools/call (PreMCPHook injects the user OBO token). Non-runner clients keep
// their own connection auth. Runner clients MUST be configured auth_type:"none" so the credStore
// does not override this header. If RunnerAudience is unset the hook injects nothing (federation
// self-disabled, like the rest of OBO); a mint FAILURE fails closed (the connection is refused, so
// the runner is never federated with a bad/absent token) — a degraded surface, never a wrong one.
func (p *OboPlugin) PreMCPConnectionHook(
	ctx *schemas.BifrostContext,
	req *schemas.BifrostMCPConnectRequest,
) (*schemas.BifrostMCPConnectRequest, *schemas.MCPConnectionShortCircuit, error) {
	if req == nil || !p.runnerClients[req.ClientName] {
		return req, nil, nil // not a runner client → its own connection auth applies
	}
	token, err := p.svc.GetRunnerConnectionToken(ctx)
	if err != nil {
		return req, blockMCPConnection("obo_conn_mint_failed", "runner connection token mint failed: "+err.Error()), nil
	}
	if token == "" {
		return req, nil, nil // RunnerAudience unset → federation self-disabled (leave the connection be)
	}
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	req.Headers["Authorization"] = "Bearer " + token
	if p.logger != nil {
		p.logger.Info("[aquadoor-obo] runner connection token injected for discovery: client=%s", req.ClientName)
	}
	return req, nil, nil
}

func (p *OboPlugin) PostMCPConnectionHook(
	_ *schemas.BifrostContext,
	resp *schemas.BifrostMCPConnectResponse,
	bifrostErr *schemas.BifrostError,
) (*schemas.BifrostMCPConnectResponse, *schemas.BifrostError, error) {
	return resp, bifrostErr, nil
}

// injectMCPHeader merges one header into BifrostContextKeyMCPExtraHeaders (forwarded to the MCP
// server iff allowlisted by the client's AllowedExtraHeaders).
func injectMCPHeader(ctx *schemas.BifrostContext, key, value string) {
	merged := map[string][]string{}
	if existing, ok := ctx.Value(schemas.BifrostContextKeyMCPExtraHeaders).(map[string][]string); ok {
		for k, v := range existing {
			merged[k] = v
		}
	}
	merged[key] = []string{value}
	ctx.SetValue(schemas.BifrostContextKeyMCPExtraHeaders, merged)
}

func blockMCP(code, msg string) *schemas.MCPPluginShortCircuit {
	return &schemas.MCPPluginShortCircuit{
		Error: &schemas.BifrostError{
			StatusCode: schemas.Ptr(403),
			Error: &schemas.ErrorField{
				Type:    schemas.Ptr("obo_guardrail"),
				Code:    schemas.Ptr(code),
				Message: msg,
			},
		},
	}
}

func blockMCPConnection(code, msg string) *schemas.MCPConnectionShortCircuit {
	return &schemas.MCPConnectionShortCircuit{
		Error: &schemas.BifrostError{
			StatusCode: schemas.Ptr(403),
			Error: &schemas.ErrorField{
				Type:    schemas.Ptr("obo_guardrail"),
				Code:    schemas.Ptr(code),
				Message: msg,
			},
		},
	}
}
