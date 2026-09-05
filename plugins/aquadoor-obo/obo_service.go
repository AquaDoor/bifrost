package aquadoorobo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuditRecord is returned alongside a token so the plugin can emit one audit line.
type AuditRecord struct {
	Email    string
	UserID   string
	Strategy string
	CacheHit bool
}

type cacheEntry struct {
	value  string
	expiry time.Time
}

// Service mints + caches runner-trusted Zitadel tokens (port of obo.py OboTokenService).
type Service struct {
	cfg             Config
	httpClient      *http.Client
	subjectProvider SubjectTokenProvider
	now             func() time.Time

	mu               sync.Mutex // guards the caches + emailLocks map (short critical sections only)
	actorToken       string
	actorExpiry      time.Time
	mgmtToken        string
	mgmtExpiry       time.Time
	runnerConnToken  string    // cached actor token scoped to the runner audience (connection discovery)
	runnerConnExpiry time.Time //
	userIDCache      map[string]cacheEntry
	exchangeCache    map[string]cacheEntry
	emailLocks       map[string]*sync.Mutex

	actorMu      sync.Mutex // serialize actor-token minting across the HTTP call
	mgmtMu       sync.Mutex // serialize mgmt-token minting
	runnerConnMu sync.Mutex // serialize runner-connection-token minting
}

type ServiceOption func(*Service)

func WithSubjectProvider(p SubjectTokenProvider) ServiceOption {
	return func(s *Service) { s.subjectProvider = p }
}
func WithNow(fn func() time.Time) ServiceOption { return func(s *Service) { s.now = fn } }

func NewService(cfg Config, hc *http.Client, opts ...ServiceOption) *Service {
	if cfg.TokenSkew == 0 {
		cfg.TokenSkew = 60 * time.Second
	}
	if cfg.UserIDCacheTTL == 0 {
		cfg.UserIDCacheTTL = time.Hour
	}
	if cfg.Strategy == "" {
		cfg.Strategy = StrategyImpersonation
	}
	s := &Service{
		cfg:           cfg,
		httpClient:    hc,
		now:           time.Now,
		userIDCache:   map[string]cacheEntry{},
		exchangeCache: map[string]cacheEntry{},
		emailLocks:    map[string]*sync.Mutex{},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Service) post(ctx context.Context, u string, body io.Reader, contentType string, headers map[string]string) (int, map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	var parsed map[string]any
	_ = json.Unmarshal(raw, &parsed)
	return resp.StatusCode, parsed, nil
}

func (s *Service) postForm(ctx context.Context, u string, form url.Values, headers map[string]string) (int, map[string]any, error) {
	return s.post(ctx, u, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", headers)
}

func (s *Service) postJSON(ctx context.Context, u string, body any, headers map[string]string) (int, map[string]any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	return s.post(ctx, u, bytes.NewReader(b), "application/json", headers)
}

func strField(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

// mintActor mints an actor access token via jwt-bearer with the given scope. Caller caches.
func (s *Service) mintActor(ctx context.Context, scope string) (string, error) {
	now := s.now()
	assertion, err := buildClientAssertion(s.cfg.ActorKey, s.cfg.Issuer, now, 10*time.Minute)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {jwtBearerGrant}, "assertion": {assertion}, "scope": {scope}}
	status, body, err := s.postForm(ctx, s.cfg.TokenURL(), form, nil)
	if err != nil {
		return "", fmt.Errorf("actor token mint (scope=%q): %w", scope, err)
	}
	at := strField(body, "access_token")
	if status != 200 || at == "" {
		return "", fmt.Errorf("actor token mint failed (scope=%q): HTTP %d %v", scope, status, body["error"])
	}
	return at, nil
}

func (s *Service) cachedActor(mgmt bool) (string, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mgmt {
		return s.mgmtToken, s.mgmtExpiry
	}
	return s.actorToken, s.actorExpiry
}

func (s *Service) storeActor(mgmt bool, tok string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mgmt {
		s.mgmtToken, s.mgmtExpiry = tok, exp
	} else {
		s.actorToken, s.actorExpiry = tok, exp
	}
}

func (s *Service) getActorTokenScoped(ctx context.Context, mgmt bool, scope string, lock *sync.Mutex) (string, error) {
	now := s.now()
	if tok, exp := s.cachedActor(mgmt); tok != "" && now.Before(exp.Add(-s.cfg.TokenSkew)) {
		return tok, nil
	}
	lock.Lock()
	defer lock.Unlock()
	now = s.now()
	if tok, exp := s.cachedActor(mgmt); tok != "" && now.Before(exp.Add(-s.cfg.TokenSkew)) {
		return tok, nil
	}
	tok, err := s.mintActor(ctx, scope)
	if err != nil {
		return "", err
	}
	s.storeActor(mgmt, tok, tokenLifetimeExpiry(tok, now, 10*time.Minute))
	return tok, nil
}

func (s *Service) getActorToken(ctx context.Context) (string, error) {
	return s.getActorTokenScoped(ctx, false, "openid "+s.cfg.BackendAudScope(), &s.actorMu)
}

func (s *Service) getMgmtToken(ctx context.Context) (string, error) {
	return s.getActorTokenScoped(ctx, true, "openid "+mgmtAudScope, &s.mgmtMu)
}

// GetRunnerConnectionToken mints (cached) an ACTOR access token scoped to the runner's MCP-caps
// audience — the machine token Bifrost presents on the runner MCP CONNECTION so it can discover the
// tool catalog (tools/list serves any authenticated caller; per-user enforcement is on tools/call
// via the OBO-injected user token). azp = the actor client (∈ the runner's allowedClientIds), aud =
// the runner project, so verifyJwt accepts it. Empty RunnerAudience → returns "" (caller skips
// injection; federation self-disabled). Serialized on its own mutex + short-lived cached.
func (s *Service) GetRunnerConnectionToken(ctx context.Context) (string, error) {
	if s.cfg.RunnerAudience == "" {
		return "", nil
	}
	s.runnerConnMu.Lock()
	defer s.runnerConnMu.Unlock()
	now := s.now()
	if s.runnerConnToken != "" && now.Before(s.runnerConnExpiry.Add(-s.cfg.TokenSkew)) {
		return s.runnerConnToken, nil
	}
	tok, err := s.mintActor(ctx, "openid "+s.cfg.RunnerAudScope())
	if err != nil {
		return "", err
	}
	s.runnerConnToken = tok
	s.runnerConnExpiry = tokenLifetimeExpiry(tok, now, 10*time.Minute)
	return s.runnerConnToken, nil
}

// IdentityAssertionEnabled reports whether the gateway identity assertion is configured (a private
// key was injected). When false the plugin injects no assertion — identity enrichment self-disabled.
func (s *Service) IdentityAssertionEnabled() bool { return s.cfg.IdentityPrivateKey != "" }

// BuildIdentityAssertion mints the gateway-signed identity assertion for (userID, email) — see
// buildIdentityAssertion. userID becomes the assertion sub (the same Zitadel id the OBO token
// authorizes), email the verified attribute the runner adopts. Uses the service clock so tests pin it.
func (s *Service) BuildIdentityAssertion(userID, email string) (string, error) {
	return buildIdentityAssertion(
		s.cfg.IdentityPrivateKey,
		s.cfg.IdentityIssuer,
		s.cfg.IdentityAudience,
		userID,
		email,
		s.now(),
		s.cfg.IdentityTTL,
	)
}

func (s *Service) resolveUserID(ctx context.Context, email string) (string, error) {
	now := s.now()
	s.mu.Lock()
	if e, ok := s.userIDCache[email]; ok && e.expiry.After(now) {
		s.mu.Unlock()
		return e.value, nil
	}
	s.mu.Unlock()

	mgmt, err := s.getMgmtToken(ctx)
	if err != nil {
		return "", err
	}
	status, body, err := s.postJSON(ctx, s.cfg.UserSearchURL(), buildUserSearchBody(email),
		map[string]string{"Authorization": "Bearer " + mgmt})
	if err != nil {
		return "", &IdentityResolutionError{fmt.Sprintf("user search for %q: %v", email, err)}
	}
	if status != 200 {
		return "", &IdentityResolutionError{fmt.Sprintf("user search for %q: HTTP %d %v", email, status, body["error"])}
	}
	userID, err := parseUserSearch(body, email)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.userIDCache[email] = cacheEntry{value: userID, expiry: now.Add(s.cfg.UserIDCacheTTL)}
	s.mu.Unlock()
	return userID, nil
}

// subject returns (subject_token, subject_token_type, resolved_user_id).
func (s *Service) subject(ctx context.Context, email, inbound string) (string, string, string, error) {
	if s.cfg.Strategy == StrategyDelegation {
		if s.subjectProvider == nil {
			return "", "", "", fmt.Errorf("delegation strategy requires a subject token provider")
		}
		tok, err := s.subjectProvider(ctx, email, inbound)
		if err != nil {
			return "", "", "", err
		}
		return tok, accessTokenType, "", nil
	}
	userID, err := s.resolveUserID(ctx, email)
	if err != nil {
		return "", "", "", err
	}
	return userID, zitadelUserIDTokenType, userID, nil
}

func (s *Service) emailLock(email string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.emailLocks[email]
	if l == nil {
		l = &sync.Mutex{}
		s.emailLocks[email] = l
	}
	return l
}

func (s *Service) cachedExchange(email string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.exchangeCache[email]
	if ok && e.expiry.Add(-s.cfg.TokenSkew).After(now) {
		return e.value, true
	}
	return "", false
}

// GetRunnerToken mints (or returns cached) a runner-trusted token for email via RFC-8693.
func (s *Service) GetRunnerToken(ctx context.Context, email, inbound string) (string, AuditRecord, error) {
	now := s.now()
	if tok, ok := s.cachedExchange(email, now); ok {
		return tok, AuditRecord{Email: email, Strategy: s.cfg.Strategy, CacheHit: true}, nil
	}
	lock := s.emailLock(email)
	lock.Lock()
	defer lock.Unlock()
	now = s.now()
	if tok, ok := s.cachedExchange(email, now); ok {
		return tok, AuditRecord{Email: email, Strategy: s.cfg.Strategy, CacheHit: true}, nil
	}

	subjectToken, subjectType, userID, err := s.subject(ctx, email, inbound)
	if err != nil {
		return "", AuditRecord{}, err
	}
	actor, err := s.getActorToken(ctx)
	if err != nil {
		return "", AuditRecord{}, err
	}
	form := url.Values{
		"grant_type":           {tokenExchangeGrant},
		"subject_token":        {subjectToken},
		"subject_token_type":   {subjectType},
		"actor_token":          {actor},
		"actor_token_type":     {accessTokenType},
		"requested_token_type": {jwtTokenType},
		"audience":             {s.cfg.BackendProjectID},
		"scope":                {"openid " + s.cfg.BackendAudScope()},
	}
	status, body, err := s.postForm(ctx, s.cfg.TokenURL(), form,
		map[string]string{"Authorization": basicAuth(s.cfg.UpstreamClientID, s.cfg.UpstreamClientSecret)})
	if err != nil {
		return "", AuditRecord{}, fmt.Errorf("token exchange for %q: %w", email, err)
	}
	tok := strField(body, "access_token")
	if status != 200 || tok == "" {
		return "", AuditRecord{}, fmt.Errorf("token exchange failed for %q: HTTP %d %v", email, status, body["error"])
	}
	fallback := 10 * time.Minute
	if ei, ok := body["expires_in"].(float64); ok && ei > 0 {
		fallback = time.Duration(ei) * time.Second
	}
	s.mu.Lock()
	s.exchangeCache[email] = cacheEntry{value: tok, expiry: tokenLifetimeExpiry(tok, now, fallback)}
	s.mu.Unlock()
	return tok, AuditRecord{Email: email, UserID: userID, Strategy: s.cfg.Strategy, CacheHit: false}, nil
}
