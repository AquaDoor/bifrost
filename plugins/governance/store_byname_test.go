package governance

import (
	"context"
	"testing"

	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
)

// GetVirtualKeyByName scans the ID index (one live entry per VK) and matches on Name. These tests
// populate that index directly, exercising the scan without the value-map's rotation-grace machinery.
func TestGetVirtualKeyByName(t *testing.T) {
	gs := &LocalGovernanceStore{}
	gs.virtualKeysByID.Store("1", &configstoreTables.TableVirtualKey{ID: "1", Name: "alice@aquadoor.dev"})
	gs.virtualKeysByID.Store("2", &configstoreTables.TableVirtualKey{ID: "2", Name: "bob@aquadoor.dev"})

	if vk, ok := gs.GetVirtualKeyByName(context.Background(), "bob@aquadoor.dev"); !ok || vk == nil || vk.ID != "2" {
		t.Fatalf("expected to find bob's VK (id=2), got ok=%v vk=%v", ok, vk)
	}
	if _, ok := gs.GetVirtualKeyByName(context.Background(), "carol@aquadoor.dev"); ok {
		t.Fatalf("absent name must return false")
	}
	if _, ok := gs.GetVirtualKeyByName(context.Background(), ""); ok {
		t.Fatalf("empty name must return false")
	}
}

// A non-*TableVirtualKey value in the index (defensive) must be skipped, not panic.
func TestGetVirtualKeyByName_SkipsJunk(t *testing.T) {
	gs := &LocalGovernanceStore{}
	gs.virtualKeysByID.Store("junk", "not-a-vk")
	gs.virtualKeysByID.Store("1", &configstoreTables.TableVirtualKey{ID: "1", Name: "alice@aquadoor.dev"})
	if vk, ok := gs.GetVirtualKeyByName(context.Background(), "alice@aquadoor.dev"); !ok || vk == nil || vk.ID != "1" {
		t.Fatalf("must skip junk and still find alice, got ok=%v vk=%v", ok, vk)
	}
}
