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
	Strategy             string
	TokenSkew            time.Duration
	UserIDCacheTTL       time.Duration
	HTTPTimeout          time.Duration
}

func (c *Config) TokenURL() string      { return strings.TrimRight(c.Issuer, "/") + "/oauth/v2/token" }
func (c *Config) UserSearchURL() string {
	return strings.TrimRight(c.Issuer, "/") + "/management/v1/users/_search"
}
func (c *Config) BackendAudScope() string {
	return fmt.Sprintf("urn:zitadel:iam:org:project:id:%s:aud", c.BackendProjectID)
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
