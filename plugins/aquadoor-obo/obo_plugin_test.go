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
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"})

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
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"})

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
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "u@aquadoor.dev"})

	ctx := mkCtx("") // no virtual key
	_, sc, _ := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner"})
	if sc == nil || sc.Error == nil || sc.Error.Error == nil || *sc.Error.Error.Code != "obo_no_identity" {
		t.Fatalf("expected obo_no_identity block, got %+v", sc)
	}
}

func TestOboPlugin_FailsClosedOnUnresolvedUser(t *testing.T) {
	m := newMockZitadel(t, []map[string]any{{"id": "user-77"}})
	svc := testService(t, m, StrategyImpersonation)
	p := NewPlugin(svc, []string{"aquadoor-runner"}, mockResolver{email: "", err: context.DeadlineExceeded})

	ctx := mkCtx("sk-bf-user")
	_, sc, _ := p.PreMCPHook(ctx, &schemas.BifrostMCPRequest{ClientName: "aquadoor-runner"})
	if sc == nil || sc.Error == nil {
		t.Fatal("expected a fail-closed block when the acting user can't be resolved")
	}
	if injectedAuth(ctx) != "" {
		t.Error("must not inject a token when identity is unresolved")
	}
}
