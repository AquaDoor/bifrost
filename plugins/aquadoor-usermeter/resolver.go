// Package aquadoorusermeter is the AquaDoor per-user cost-metering plugin (#1814). LibreChat sends
// the caller's email as a vouched header on its direct-to-Bifrost LLM egress; this plugin resolves
// that email to the user's per-user Virtual Key and rewrites the presented credential in
// HTTPTransportPreAuthHook (the interface's blessed "derive a virtual key from an upstream identity
// header" pattern), so Bifrost's native governance meters cost + enforces budget/rate PER USER —
// uniformly with the already-per-user MCP path (VK name == the user's email).
//
// It RESOLVES only; it never provisions a VK (the zitadel-broker is the single VK writer, since only
// it knows the user's caps). Fail-closed: a vouched email with no VK is blocked, never silently
// metered to the shared service VK (which would mis-attribute cost).
package aquadoorusermeter

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
)

// VKStore is the narrow config-store capability the resolver needs: look up a VK by its unique name
// (AquaDoor sets the name to the owner's lowercased email). *configstore.RDBConfigStore implements
// it. Deliberately minimal (interface segregation) — the plugin never depends on the full
// ConfigStore surface, so adding this method touched no shared interface and broke no mock.
type VKStore interface {
	GetVirtualKeyByName(ctx context.Context, name string) (*configstoreTables.TableVirtualKey, error)
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

// Resolver maps a vouched end-user email to that user's Bifrost VK value, with a short TTL cache so
// the hot LLM path does not hit the DB on every request. ONLY positive results are cached; a miss
// or a store error is never cached — a just-provisioned VK must become visible immediately, and a
// miss must keep failing closed rather than being pinned for a TTL.
type Resolver struct {
	store VKStore
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]cacheEntry
	now   func() time.Time // injectable for tests
}

// NewResolver builds a resolver with the given cache TTL (defaults to 60s when non-positive).
func NewResolver(store VKStore, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Resolver{
		store: store,
		ttl:   ttl,
		cache: make(map[string]cacheEntry),
		now:   time.Now,
	}
}

// ResolveVKValue returns the VK value (sk-bf-…) for a user email. found=false means no VK exists for
// that email (the caller must fail closed). A non-nil err is a store failure (the caller also fails
// closed on it — never a silent fallthrough).
func (r *Resolver) ResolveVKValue(ctx context.Context, email string) (value string, found bool, err error) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return "", false, nil
	}

	now := r.now()
	r.mu.RLock()
	if e, ok := r.cache[key]; ok && now.Before(e.expiresAt) {
		r.mu.RUnlock()
		return e.value, true, nil
	}
	r.mu.RUnlock()

	vk, err := r.store.GetVirtualKeyByName(ctx, key)
	if err != nil {
		if errors.Is(err, configstore.ErrNotFound) {
			return "", false, nil // no VK for this email → caller fails closed
		}
		return "", false, err
	}
	if vk == nil {
		return "", false, nil
	}
	val := vk.Value.GetValue()
	if val == "" {
		// A VK row with no resolvable secret can't be presented — treat as a miss (fail-closed).
		return "", false, nil
	}

	r.mu.Lock()
	r.cache[key] = cacheEntry{value: val, expiresAt: now.Add(r.ttl)}
	r.mu.Unlock()
	return val, true, nil
}
