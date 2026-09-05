// Package aquadoorobo mints runner-trusted Zitadel tokens for inbound per-user MCP tool calls,
// via RFC-8693 token-exchange (Bifrost unified gateway, #1780 §7.2). It is a faithful Go port of
// infra/cf-plugins/aquadoor_obo/obo.py (the CF OBO engine) — the protocol is Zitadel's, not CF's,
// so it carries over unchanged. The Bifrost PreMCPHook adapter (obo_plugin.go) calls
// Service.GetRunnerToken and injects the token as the runner Authorization header.
//
// Fail-closed throughout: a missing/ambiguous identity, a failed exchange, or a mint failure all
// return an error (the plugin turns it into an MCPPluginShortCircuit — never a silent pass).
package aquadoorobo

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtBearerGrant         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	tokenExchangeGrant     = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType        = "urn:ietf:params:oauth:token-type:access_token"
	jwtTokenType           = "urn:ietf:params:oauth:token-type:jwt"
	zitadelUserIDTokenType = "urn:zitadel:params:oauth:token-type:user_id"
	mgmtAudScope           = "urn:zitadel:iam:org:project:id:zitadel:aud"

	StrategyImpersonation = "impersonation"
	StrategyDelegation    = "delegation"

	// Gateway identity-assertion protocol constants (#1780 §7.2 / #1804 / #1798-A3). They MUST match
	// the runner's verifyGatewayIdentity defaults (mono packages/mcp-foundation/src/gateway-identity.ts).
	// Production threads BOTH from a single infra source (infra/src/config.ts → env) so they cannot
	// drift across the two repos; dev/test fall back to these literals (identical on both sides).
	DefaultIdentityIssuer   = "aquadoor-gateway"
	DefaultIdentityAudience = "aquadoor-mcp-runner"
	// DefaultIdentityTTL bounds the assertion's replay window. It is a per-call presenter proof, so a
	// short life is correct (a runner call completes in well under a minute).
	DefaultIdentityTTL = 120 * time.Second
)

// IdentityResolutionError is a fail-closed 0/many email→userId result.
type IdentityResolutionError struct{ msg string }

func (e *IdentityResolutionError) Error() string { return e.msg }

// ActorKey is the Zitadel MachineKey JSON ({userId, keyId, key=PEM}).
type ActorKey struct {
	UserID string `json:"userId"`
	KeyID  string `json:"keyId"`
	Key    string `json:"key"`
}

// SubjectTokenProvider yields a genuine user access token (delegation strategy).
type SubjectTokenProvider func(ctx context.Context, email, inboundToken string) (string, error)

type Config struct {
	Issuer               string
	BackendProjectID     string
	ActorKey             ActorKey
	UpstreamClientID     string
	UpstreamClientSecret string
	RunnerToolPrefixes   []string
	// RunnerClients are the Bifrost MCP client names that federate the AquaDoor runners — only MCP
	// calls to these clients get an OBO token (Outline/etc. keep their own static auth). Passed to
	// NewPlugin as the runner-client allow-set.
	RunnerClients []string
	Strategy      string
	// RunnerAudience is the runner's MCP-caps project id — the `aud` of the machine ACTOR token
	// Bifrost presents on the runner MCP CONNECTION for tool discovery (tools/list serves any
	// authenticated caller; per-user enforcement is on tools/call via the OBO-injected user token).
	// Empty → the connection hook injects nothing (federation self-disabled, like the other OBO env).
	RunnerAudience string
	TokenSkew      time.Duration
	UserIDCacheTTL time.Duration
	HTTPTimeout    time.Duration

	// --- Gateway identity assertion (#1780 §7.2 / #1804 / #1798-A3) ------------------------------
	// The OBO token-exchange DROPS every non-grant claim (metadata-sourced claims — email included —
	// do not survive the impersonation exchange; only grant-derived caps/bundles do). So the acting
	// user's VERIFIED email — which dekart needs as author_email for per-user map ownership — cannot
	// ride the Zitadel token. Instead the gateway signs a minimal RS256 identity assertion carrying
	// {iss, sub=zitadelUserId, email, aud, exp} that the runner verifies with the matching public key
	// and binds to the OBO token's sub. It carries NO caps: authorization stays Zitadel's, minted
	// un-inflatably by the exchange and independently re-verified at the runner, so a stolen gateway
	// key can never inflate caps — it can only attest email for real, already-authorized users. The
	// assertion doubles as the gateway proof-of-presenter (only the gateway holds this key), so a
	// smuggled OBO token alone cannot satisfy an assertion-requiring runner.

	// IdentityPrivateKey is the gateway RS256 private key PEM (SECRET; injected from env in
	// plugins.go, never config.json). Empty → no assertion is minted (identity enrichment self-
	// disabled, like the rest of OBO env).
	IdentityPrivateKey string
	// IdentityIssuer / IdentityAudience are the assertion's iss/aud (non-secret; config.json).
	// Empty → DefaultIdentityIssuer / DefaultIdentityAudience.
	IdentityIssuer   string
	IdentityAudience string
	// IdentityTTL bounds the assertion lifetime. <=0 → DefaultIdentityTTL.
	IdentityTTL time.Duration
}

func (c *Config) TokenURL() string { return strings.TrimRight(c.Issuer, "/") + "/oauth/v2/token" }
func (c *Config) UserSearchURL() string {
	return strings.TrimRight(c.Issuer, "/") + "/management/v1/users/_search"
}
func (c *Config) BackendAudScope() string {
	return fmt.Sprintf("urn:zitadel:iam:org:project:id:%s:aud", c.BackendProjectID)
}

// RunnerAudScope is the Zitadel project-audience reservation scope for the runner's MCP-caps
// project — mints an actor token whose `aud` the runner's verifyJwt accepts for connection discovery.
func (c *Config) RunnerAudScope() string {
	return fmt.Sprintf("urn:zitadel:iam:org:project:id:%s:aud", c.RunnerAudience)
}

// IsRunnerTool reports whether name (the federated tool name) is a first-party runner tool that
// must get an OBO token. Matches the runner federation slug prefix, never the bare tool name.
func (c *Config) IsRunnerTool(name string) bool {
	if name == "" {
		return false
	}
	for _, p := range c.RunnerToolPrefixes {
		if p != "" && strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// --- pure helpers (faithful to obo.py) --------------------------------------

func parseRSAKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("actor key: not a PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("actor key: parse: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("actor key: not an RSA key")
	}
	return rk, nil
}

// buildClientAssertion signs an RS256 private_key_jwt with the MachineKey (iss=sub=userId,
// aud=issuer), matching obo.py.build_client_assertion.
func buildClientAssertion(k ActorKey, issuer string, now time.Time, ttl time.Duration) (string, error) {
	if k.UserID == "" || k.KeyID == "" || k.Key == "" {
		return "", errors.New("actor key JSON missing userId/keyId/key")
	}
	rk, err := parseRSAKey(k.Key)
	if err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": k.UserID,
		"sub": k.UserID,
		"aud": strings.TrimRight(issuer, "/"),
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
	tok.Header["kid"] = k.KeyID
	return tok.SignedString(rk)
}

// decodePEM accepts either a raw PEM string ("-----BEGIN …") or a base64-of-PEM string (how the key
// is carried through env/compose/pulumi without newline escaping) and returns the raw PEM. This is
// the single decode boundary so callers always work with PEM.
func decodePEM(v string) (string, error) {
	if strings.Contains(v, "-----BEGIN") {
		return v, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return "", fmt.Errorf("key is neither PEM nor base64-of-PEM: %w", err)
	}
	return string(raw), nil
}

// buildIdentityAssertion signs the gateway identity assertion — a minimal RS256 JWT that delivers the
// acting user's VERIFIED email (with the Zitadel user id as sub) to the runner. It is NOT an authz
// token: it carries NO caps (those stay Zitadel's), only the email attribute the OBO exchange drops,
// cryptographically bound to the same sub the OBO token authorizes. See Config's identity block.
func buildIdentityAssertion(privKey, issuer, audience, sub, email string, now time.Time, ttl time.Duration) (string, error) {
	if privKey == "" {
		return "", errors.New("gateway identity private key not configured")
	}
	if sub == "" || email == "" {
		return "", errors.New("gateway identity assertion needs both sub and email")
	}
	pemStr, err := decodePEM(privKey)
	if err != nil {
		return "", fmt.Errorf("gateway identity key: %w", err)
	}
	rk, err := parseRSAKey(pemStr)
	if err != nil {
		return "", fmt.Errorf("gateway identity key: %w", err)
	}
	if issuer == "" {
		issuer = DefaultIdentityIssuer
	}
	if audience == "" {
		audience = DefaultIdentityAudience
	}
	if ttl <= 0 {
		ttl = DefaultIdentityTTL
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuer,
		"sub":   sub,
		"email": email,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
	})
	return tok.SignedString(rk)
}

func buildUserSearchBody(email string) map[string]any {
	return map[string]any{
		"queries": []any{
			map[string]any{"emailQuery": map[string]any{
				"emailAddress": email,
				"method":       "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE",
			}},
		},
	}
}

// parseUserSearch returns the single userId, or a fail-closed error on 0/many matches.
func parseUserSearch(body map[string]any, email string) (string, error) {
	result, _ := body["result"].([]any)
	var ids []string
	for _, r := range result {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			id, _ = m["userId"].(string)
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	switch {
	case len(ids) == 1:
		return ids[0], nil
	case len(ids) == 0:
		return "", &IdentityResolutionError{fmt.Sprintf("no Zitadel user for email %q", email)}
	default:
		return "", &IdentityResolutionError{fmt.Sprintf("ambiguous Zitadel users for email %q (%d matches)", email, len(ids))}
	}
}

// tokenLifetimeExpiry reads exp from a JWT (best-effort), else now+fallback.
func tokenLifetimeExpiry(token string, now time.Time, fallback time.Duration) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var claims struct {
				Exp int64 `json:"exp"`
			}
			if json.Unmarshal(raw, &claims) == nil && claims.Exp > 0 {
				return time.Unix(claims.Exp, 0)
			}
		}
	}
	return now.Add(fallback)
}

func basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}
