package aquadoorobo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testActorKey(t *testing.T) ActorKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return ActorKey{UserID: "actor-uid", KeyID: "kid-1", Key: string(pemBytes)}
}

// mockZitadel routes the token + user-search endpoints. Counters expose call counts for caching.
type mockZitadel struct {
	srv          *httptest.Server
	jwtBearer    int32 // actor mints
	exchange     int32 // token exchanges
	search       int32 // user searches
	searchResult []map[string]any
}

func newMockZitadel(t *testing.T, searchResult []map[string]any) *mockZitadel {
	m := &mockZitadel{searchResult: searchResult}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.PostForm.Get("grant_type") {
		case jwtBearerGrant:
			atomic.AddInt32(&m.jwtBearer, 1)
			_, _ = w.Write([]byte(`{"access_token":"actor-token","expires_in":600}`))
		case tokenExchangeGrant:
			atomic.AddInt32(&m.exchange, 1)
			_, _ = w.Write([]byte(`{"access_token":"exchanged-token","expires_in":600}`))
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
		}
	})
	mux.HandleFunc("/management/v1/users/_search", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&m.search, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": m.searchResult})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func testService(t *testing.T, m *mockZitadel, strategy string) *Service {
	cfg := Config{
		Issuer:               m.srv.URL,
		BackendProjectID:     "backend-proj",
		ActorKey:             testActorKey(t),
		UpstreamClientID:     "cf",
		UpstreamClientSecret: "sekret",
		RunnerToolPrefixes:   []string{"aquadoor-runner-"},
		Strategy:             strategy,
	}
	return NewService(cfg, m.srv.Client())
}

func TestBuildClientAssertion_ValidRS256(t *testing.T) {
	k := testActorKey(t)
	now := time.Now()
	tok, err := buildClientAssertion(k, "https://id.example", now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(k.Key))
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	parsed, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return &priv.PublicKey, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("assertion not verifiable: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "actor-uid" || claims["sub"] != "actor-uid" || claims["aud"] != "https://id.example" {
		t.Errorf("bad claims: %v", claims)
	}
	if parsed.Header["kid"] != "kid-1" {
		t.Errorf("bad kid: %v", parsed.Header["kid"])
	}
}

func TestParseUserSearch_FailClosed(t *testing.T) {
	if _, err := parseUserSearch(map[string]any{"result": []any{}}, "a@b"); err == nil {
		t.Error("zero matches must fail closed")
	}
	two := map[string]any{"result": []any{map[string]any{"id": "1"}, map[string]any{"id": "2"}}}
	if _, err := parseUserSearch(two, "a@b"); err == nil {
		t.Error("multiple matches must fail closed")
	}
	one := map[string]any{"result": []any{map[string]any{"id": "u-42"}}}
	id, err := parseUserSearch(one, "a@b")
	if err != nil || id != "u-42" {
		t.Errorf("single match: id=%q err=%v", id, err)
	}
}

func TestGetRunnerToken_ImpersonationHappyPath(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	s := testService(t, m, StrategyImpersonation)
	tok, audit, err := s.GetRunnerToken(context.Background(), "u@aquadoor.dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "exchanged-token" {
		t.Errorf("token=%q", tok)
	}
	if audit.UserID != "user-77" || audit.CacheHit {
		t.Errorf("audit=%+v", audit)
	}
	if atomic.LoadInt32(&m.exchange) != 1 || atomic.LoadInt32(&m.search) != 1 {
		t.Errorf("exchange=%d search=%d", m.exchange, m.search)
	}
}

func TestGetRunnerToken_CachesPerEmail(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	s := testService(t, m, StrategyImpersonation)
	ctx := context.Background()
	_, _, _ = s.GetRunnerToken(ctx, "u@aquadoor.dev", "")
	_, audit, err := s.GetRunnerToken(ctx, "u@aquadoor.dev", "")
	if err != nil {
		t.Fatal(err)
	}
	if !audit.CacheHit {
		t.Error("second call should be a cache hit")
	}
	if atomic.LoadInt32(&m.exchange) != 1 {
		t.Errorf("expected 1 exchange (cached), got %d", m.exchange)
	}
}

func TestGetRunnerToken_FailClosedNoUser(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{}) // zero matches
	s := testService(t, m, StrategyImpersonation)
	_, _, err := s.GetRunnerToken(context.Background(), "ghost@aquadoor.dev", "")
	if err == nil {
		t.Fatal("expected fail-closed error when no Zitadel user resolves")
	}
	var ire *IdentityResolutionError
	if !as(err, &ire) {
		t.Errorf("expected IdentityResolutionError, got %T", err)
	}
	if atomic.LoadInt32(&m.exchange) != 0 {
		t.Error("must not exchange when identity is unresolved")
	}
}

func TestIsRunnerTool(t *testing.T) {
	c := &Config{RunnerToolPrefixes: []string{"aquadoor-runner-"}}
	if !c.IsRunnerTool("aquadoor-runner-catalog-catalog_search") {
		t.Error("runner tool should match")
	}
	if c.IsRunnerTool("outline_read") {
		t.Error("non-runner tool must not match")
	}
}

// as is a tiny errors.As shim (avoids importing errors just for the test signature).
func as(err error, target **IdentityResolutionError) bool {
	for err != nil {
		if e, ok := err.(*IdentityResolutionError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
