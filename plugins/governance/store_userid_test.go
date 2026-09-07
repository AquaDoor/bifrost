package governance

import (
	"context"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/grant"
)

// #1814 §1c Stage F: StampVirtualKeyScope derives logs.user_id from the VK name (=email) for the
// per-user cost dimension, GUARDED — only email-shaped names, only when unset.
func userID(ctx *schemas.BifrostContext) string {
	s, _ := ctx.Value(schemas.BifrostContextKeyUserID).(string)
	return s
}

// A context with a grant installed, as the transport always does before governance runs.
func ctxWithGrant() *schemas.BifrostContext {
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetGrant(grant.New())
	return ctx
}

func TestStampVirtualKeyScope_DerivesUserIdFromEmailName(t *testing.T) {
	ctx := ctxWithGrant()
	StampVirtualKeyScope(ctx, &configstoreTables.TableVirtualKey{ID: "1", Name: "alice@aquadoor.dev"})
	if got := userID(ctx); got != "alice@aquadoor.dev" {
		t.Fatalf("expected user_id derived from the email-shaped VK name, got %q", got)
	}
}

func TestStampVirtualKeyScope_ServiceVkNameDoesNotPolluteUserDimension(t *testing.T) {
	ctx := ctxWithGrant()
	// A non-email (service/system) VK name must NOT be stamped as a user (no phantom user in the histogram).
	StampVirtualKeyScope(ctx, &configstoreTables.TableVirtualKey{ID: "2", Name: "librechat-service"})
	if got := userID(ctx); got != "" {
		t.Fatalf("service VK name must not set user_id, got %q", got)
	}
}

func TestStampVirtualKeyScope_DoesNotShadowExistingUser(t *testing.T) {
	ctx := ctxWithGrant()
	ctx.SetValue(schemas.BifrostContextKeyUserID, "real-idp-subject") // e.g. an MCP OAuth subject settled earlier
	StampVirtualKeyScope(ctx, &configstoreTables.TableVirtualKey{ID: "3", Name: "alice@aquadoor.dev"})
	if got := userID(ctx); got != "real-idp-subject" {
		t.Fatalf("must not shadow an already-settled user, got %q", got)
	}
}
