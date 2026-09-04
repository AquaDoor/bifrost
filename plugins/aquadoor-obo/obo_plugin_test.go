package aquadoorobo

import (
	"context"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

type mockResolver struct {
	email string
	err   error
}

func (m mockResolver) EmailForVK(_ context.Context, _ string) (string, error) {
	return m.email, m.err
}

func mkCtx(vk string) *schemas.BifrostContext {
	bc := schemas.NewBifrostContextWithValue(context.Background(), time.Time{}, "seed", "x")
	if vk != "" {
		bc.SetValue(schemas.BifrostContextKeyVirtualKey, vk)
	}
	return bc
}

func injectedAuth(ctx *schemas.BifrostContext) string {
	h, ok := ctx.Value(schemas.BifrostContextKeyMCPExtraHeaders).(map[string][]string)
	if !ok {
		return ""
	}
	if v := h["Authorization"]; len(v) == 1 {
		return v[0]
	}
	return ""
}

func TestOboPlugin_InjectsTokenForRunnerClient(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := testService(t, m, StrategyImpersonation)
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	ctx := mkCtx("sk-bf-user")
	req := &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner"}
	out, sc, err := p.PreMCPHook(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if sc != nil {
		t.Fatalf("unexpected short-circuit: %+v", sc.Error)
	}
	if out.ClientName != "aquadoor-runner" {
		t.Errorf("req mangled: %+v", out)
	}
	if got := injectedAuth(ctx); got != "Bearer exchanged-token" {
		t.Errorf("Authorization not injected: %q", got)
	}
}

func TestOboPlugin_IgnoresNonRunnerClient(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := testService(t, m, StrategyImpersonation)
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	ctx := mkCtx("sk-bf-user")
	_, sc, err := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "outline"})
	if err != nil || sc != nil {
		t.Fatalf("non-runner client must pass through: sc=%v err=%v", sc, err)
	}
	if injectedAuth(ctx) != "" {
		t.Error("must NOT inject OBO auth for a non-runner client")
	}
}

func TestOboPlugin_FailsClosedWithoutVK(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := testService(t, m, StrategyImpersonation)
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	ctx := mkCtx("") // no virtual key
	_, sc, _ := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner"})
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || *sc.Error.Error.Code != "obo_no_identity" {
		t.Fatalf("expected obo_no_identity block, got %+v", sc)
	}
}

func connSvc(t *testing.T, m *mockZitadel, runnerAud string) *Service {
	t.Helper()
	return NewService(Config{
		Issuer:         m.srv.URL,
		ActorKey:       testActorKey(t),
		RunnerAudience: runnerAud,
		Strategy:       StrategyImpersonation,
	}, m.srv.Client())
}

func TestOboPlugin_ConnectionInjectsRunnerToken(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	p := NewPlugin(connSvc(t, m, "runner-proj"), []string{"aquadoor-runner-catalog"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	req := &schemas.BifrostMCPConnectRequest{ClientName: "aquadoor-runner-catalog"}
	out, sc, err := p.PreMCPConnectionHook(mkCtx(""), req)
	if err != nil {
		t.Fatal(err)
	}
	if sc != nil {
		t.Fatalf("unexpected short-circuit: %+v", sc.Error)
	}
	if out.Headers["Authorization"] != "Bearer actor-token" {
		t.Errorf("connection discovery token not injected: %q", out.Headers["Authorization"])
	}
}

func TestOboPlugin_ConnectionSkipsNonRunnerClient(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	p := NewPlugin(connSvc(t, m, "runner-proj"), []string{"aquadoor-runner-catalog"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	out, sc, err := p.PreMCPConnectionHook(mkCtx(""), &schemas.BifrostMCPConnectRequest{ClientName: "outline"})
	if err != nil || sc != nil {
		t.Fatalf("non-runner client must pass through: sc=%v err=%v", sc, err)
	}
	if out.Headers["Authorization"] != "" {
		t.Error("must NOT inject a discovery token for a non-runner client")
	}
}

func TestOboPlugin_ConnectionNoopWhenAudienceUnset(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	// RunnerAudience "" → federation self-disabled: the hook injects nothing (no token minted).
	p := NewPlugin(connSvc(t, m, ""), []string{"aquadoor-runner-catalog"}, mockResolver{email: "u@aquadoor.dev"}, nil)

	req := &schemas.BifrostMCPConnectRequest{ClientName: "aquadoor-runner-catalog"}
	out, sc, err := p.PreMCPConnectionHook(mkCtx(""), req)
	if err != nil || sc != nil {
		t.Fatalf("unset audience must be a no-op pass-through: sc=%v err=%v", sc, err)
	}
	if out.Headers["Authorization"] != "" {
		t.Error("must NOT inject a discovery token when RunnerAudience is unset")
	}
}

func TestOboPlugin_FailsClosedOnUnresolvedUser(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := testService(t, m, StrategyImpersonation)
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "", err: context.DeadlineExceeded}, nil)

	ctx := mkCtx("sk-bf-user")
	_, sc, _ := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner"})
	if sc == nil || sc.Error == nil {
		t.Fatal("expected a fail-closed block when the acting user can't be resolved")
	}
	if injectedAuth(ctx) != "" {
		t.Error("must not inject a token when identity is unresolved")
	}
}
