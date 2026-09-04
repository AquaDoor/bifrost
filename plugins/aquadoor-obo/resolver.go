package aquadoorobo

import (
	"context"
	"errors"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// GovernanceVKNameResolver resolves the acting user's email from the governance-stamped virtual-key
// NAME in the Bifrost context. The caps→VK bridge (broker, #1780 §7.3) mints each per-user VK with
// name = the user's email, and the governance plugin stamps that name into the context
// (BifrostContextKeyGovernanceVirtualKeyName) once it has authenticated the presented VK. OBO
// therefore reads a VERIFIED acting identity from context — no governance-store lookup, and no
// spoofable X-Aquadoor-Act-Email header (the #1777 fix). It is fail-closed: an empty/missing VK
// name yields an error, which the plugin turns into an MCPPluginShortCircuit (the runner call is
// refused rather than sent with a wrong / capless identity).
//
// Ordering contract: the governance plugin MUST run before the OBO PreMCPHook (lower plugin order),
// so the VK name is already stamped when this resolver is consulted.
type GovernanceVKNameResolver struct{}

var _ EmailResolver = GovernanceVKNameResolver{}

// EmailForVK ignores the raw VK value and reads the governance-verified VK name (= email) off the
// context. The value form is kept in the signature for the EmailResolver contract / alternate
// implementations (e.g. a store-backed resolver).
func (GovernanceVKNameResolver) EmailForVK(ctx context.Context, _ string) (string, error) {
	if email := bifrost.GetStringFromContext(ctx, schemas.BifrostContextKeyGovernanceVirtualKeyName); email != "" {
		return email, nil
	}
	return "", errors.New("aquadoor-obo: no governance virtual-key name in context — governance must run before OBO, and the VK name must be the acting user's email")
}
