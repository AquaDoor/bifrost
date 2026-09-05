package aquadoorobo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maximhq/bifrost/core/schemas"
)

// testGatewayKey returns a fresh RSA key as a PKCS8 PEM (the format the real gateway key uses) plus
// its public key for verification.
func testGatewayKey(t *testing.T) (privPEM string, pub *rsa.PublicKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), &k.PublicKey
}

func parseIdentity(t *testing.T, tok string, pub *rsa.PublicKey) jwt.MapClaims {
	t.Helper()
	parsed, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("identity assertion not verifiable: %v", err)
	}
	return parsed.Claims.(jwt.MapClaims)
}

func injectedHeader(ctx *schemas.BifrostContext, key string) string {
	h, ok := ctx.Value(schemas.BifrostContextKeyMCPExtraHeaders).(map[string][]string)
	if !ok {
		return ""
	}
	if v := h[key]; len(v) == 1 {
		return v[0]
	}
	return ""
}

func TestDecodePEM_RawAndBase64(t *testing.T) {
	priv, _ := testGatewayKey(t)
	got, err := decodePEM(priv)
	if err != nil || got != priv {
		t.Fatalf("raw PEM must pass through unchanged: err=%v", err)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(priv))
	got, err = decodePEM(b64)
	if err != nil || got != priv {
		t.Fatalf("base64-of-PEM must decode to the raw PEM: err=%v got=%q", err, got[:20])
	}
	if _, err := decodePEM("not-pem-not-base64-!!!"); err == nil {
		t.Error("garbage that is neither PEM nor base64 must error")
	}
}

func TestBuildIdentityAssertion_ValidRS256(t *testing.T) {
	priv, pub := testGatewayKey(t)
	now := time.Now()
	tok, err := buildIdentityAssertion(priv, "aquadoor-gateway", "aquadoor-mcp-runner", "user-77", "u@aquadoor.dev", now, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := parseIdentity(t, tok, pub)
	if c["iss"] != "aquadoor-gateway" || c["aud"] != "aquadoor-mcp-runner" {
		t.Errorf("bad iss/aud: %v", c)
	}
	if c["sub"] != "user-77" || c["email"] != "u@aquadoor.dev" {
		t.Errorf("bad sub/email: %v", c)
	}
	if int64(c["exp"].(float64)) != now.Add(90*time.Second).Unix() {
		t.Errorf("bad exp: %v", c["exp"])
	}
	// The assertion carries NO caps — authorization stays with the Zitadel OBO token.
	if _, ok := c["urn:aquadoor:caps"]; ok {
		t.Error("identity assertion must NOT carry caps")
	}
}

func TestBuildIdentityAssertion_DefaultsAndBase64Key(t *testing.T) {
	priv, pub := testGatewayKey(t)
	b64 := base64.StdEncoding.EncodeToString([]byte(priv))
	now := time.Now()
	// Empty iss/aud/ttl fall back to the protocol defaults; a base64-of-PEM key is accepted.
	tok, err := buildIdentityAssertion(b64, "", "", "user-9", "z@aquadoor.dev", now, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := parseIdentity(t, tok, pub)
	if c["iss"] != DefaultIdentityIssuer || c["aud"] != DefaultIdentityAudience {
		t.Errorf("defaults not applied: %v", c)
	}
	if int64(c["exp"].(float64)) != now.Add(DefaultIdentityTTL).Unix() {
		t.Errorf("default TTL not applied: %v", c["exp"])
	}
}

func TestBuildIdentityAssertion_FailClosed(t *testing.T) {
	priv, _ := testGatewayKey(t)
	if _, err := buildIdentityAssertion("", "i", "a", "s", "e@x", time.Now(), time.Minute); err == nil {
		t.Error("empty key must error")
	}
	if _, err := buildIdentityAssertion(priv, "i", "a", "", "e@x", time.Now(), time.Minute); err == nil {
		t.Error("empty sub must error")
	}
	if _, err := buildIdentityAssertion(priv, "i", "a", "s", "", time.Now(), time.Minute); err == nil {
		t.Error("empty email must error")
	}
}

// identitySvc builds an OBO Service with the gateway identity assertion configured, over the mock
// Zitadel (so GetRunnerToken resolves user-77 + returns the exchanged token).
func identitySvc(t *testing.T, m *mockZitadel, privPEM string) *Service {
	t.Helper()
	cfg := Config{
		Issuer:               m.srv.URL,
		BackendProjectID:     "backend-proj",
		ActorKey:             testActorKey(t),
		UpstreamClientID:     "cf",
		UpstreamClientSecret: "sekret",
		RunnerToolPrefixes:   []string{"aquadoor-runner-"},
		Strategy:             StrategyImpersonation,
		IdentityPrivateKey:   privPEM,
		IdentityIssuer:       "aquadoor-gateway",
		IdentityAudience:     "aquadoor-mcp-runner",
	}
	return NewService(cfg, m.srv.Client())
}

func TestOboPlugin_InjectsIdentityAssertionBoundToSub(t *testing.T) {
	priv, pub := testGatewayKey(t)
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := identitySvc(t, m, priv)
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	ctx := mkCtx("sk-bf-user")
	_, sc, err := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner", RequestType: schemas.MCPRequestTypeExecuteTool})
	if err != nil || sc != nil {
		t.Fatalf("unexpected block/err: sc=%v err=%v", sc, err)
	}
	// The OBO token still rides Authorization…
	if injectedAuth(ctx) != "Bearer exchanged-token" {
		t.Errorf("OBO Authorization not injected: %q", injectedAuth(ctx))
	}
	// …and the gateway identity assertion rides its own header, bound to the resolved Zitadel sub.
	assertion := injectedHeader(ctx, "X-Aquadoor-Gateway-Identity")
	if assertion == "" {
		t.Fatal("X-Aquadoor-Gateway-Identity not injected")
	}
	c := parseIdentity(t, assertion, pub)
	if c["sub"] != "user-77" {
		t.Errorf("assertion sub must equal the OBO-resolved userId (user-77), got %v", c["sub"])
	}
	if c["email"] != "u@aquadoor.dev" {
		t.Errorf("assertion email must equal the acting user, got %v", c["email"])
	}
}

// Regression (#1804): the assertion must be injected on a CACHE-HIT call too. The first call mints +
// caches the exchange; the second serves it from cache. Before the fix the cache-hit AuditRecord had
// an empty UserID, so BuildIdentityAssertion failed "needs both sub and email" and fail-closed the
// whole tool call — exactly the live failure. Both calls must carry a sub-bound assertion.
func TestOboPlugin_InjectsIdentityAssertionOnCacheHit(t *testing.T) {
	priv, pub := testGatewayKey(t)
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := identitySvc(t, m, priv)
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	for i, label := range []string{"fresh-mint", "cache-hit"} {
		ctx := mkCtx("sk-bf-user")
		_, sc, err := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner", RequestType: schemas.MCPRequestTypeExecuteTool})
		if err != nil || sc != nil {
			t.Fatalf("%s: unexpected block/err: sc=%v err=%v", label, sc, err)
		}
		assertion := injectedHeader(ctx, "X-Aquadoor-Gateway-Identity")
		if assertion == "" {
			t.Fatalf("%s: assertion not injected (call %d)", label, i)
		}
		c := parseIdentity(t, assertion, pub)
		if c["sub"] != "user-77" || c["email"] != "u@aquadoor.dev" {
			t.Errorf("%s: bad assertion claims: %v", label, c)
		}
	}
}

func TestOboPlugin_NoIdentityAssertionWhenKeyUnset(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := testService(t, m, StrategyImpersonation) // no IdentityPrivateKey
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	ctx := mkCtx("sk-bf-user")
	_, sc, err := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner", RequestType: schemas.MCPRequestTypeExecuteTool})
	if err != nil || sc != nil {
		t.Fatalf("unexpected block/err: sc=%v err=%v", sc, err)
	}
	if injectedAuth(ctx) != "Bearer exchanged-token" {
		t.Error("OBO Authorization must still be injected")
	}
	if injectedHeader(ctx, "X-Aquadoor-Gateway-Identity") != "" {
		t.Error("no assertion must be injected when the gateway key is unset (self-disabled)")
	}
}

// A garbage identity key must fail the call CLOSED (never send an OBO token with an unattested
// identity), not silently skip the assertion.
func TestOboPlugin_FailsClosedOnBadIdentityKey(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := identitySvc(t, m, "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----")
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	ctx := mkCtx("sk-bf-user")
	_, sc, _ := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner", RequestType: schemas.MCPRequestTypeExecuteTool})
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || *sc.Error.Error.Code != "obo_identity_failed" {
		t.Fatalf("expected obo_identity_failed block, got %+v", sc)
	}
	if strings.Contains(injectedHeader(ctx, "X-Aquadoor-Gateway-Identity"), ".") {
		t.Error("must not inject an assertion when signing failed")
	}
}
