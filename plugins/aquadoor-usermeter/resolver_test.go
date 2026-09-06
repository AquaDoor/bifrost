package aquadoorusermeter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	configstoreTables "github.com/maximhq/bifrost/framework/configstore/tables"
)

type fakeStore struct {
	vks   map[string]*configstoreTables.TableVirtualKey
	err   error
	calls int
}

func (f *fakeStore) GetVirtualKeyByName(_ context.Context, name string) (*configstoreTables.TableVirtualKey, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	vk, ok := f.vks[name]
	if !ok {
		return nil, configstore.ErrNotFound
	}
	return vk, nil
}

func vk(name, value string) *configstoreTables.TableVirtualKey {
	return &configstoreTables.TableVirtualKey{Name: name, Value: schemas.SecretVar{Val: value}}
}

func TestResolveVKValue_KnownEmail(t *testing.T) {
	store := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{
		"user@aquadoor.dev": vk("user@aquadoor.dev", "sk-bf-user-123"),
	}}
	r := NewResolver(store, time.Minute)
	val, found, err := r.ResolveVKValue(context.Background(), "user@aquadoor.dev")
	if err != nil || !found || val != "sk-bf-user-123" {
		t.Fatalf("want (sk-bf-user-123,true,nil) got (%q,%v,%v)", val, found, err)
	}
}

func TestResolveVKValue_LowercasesEmail(t *testing.T) {
	store := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{
		"user@aquadoor.dev": vk("user@aquadoor.dev", "sk-bf-user-123"),
	}}
	r := NewResolver(store, time.Minute)
	// Uppercase / padded input must resolve against the lowercased VK name.
	val, found, err := r.ResolveVKValue(context.Background(), "  User@AquaDoor.DEV  ")
	if err != nil || !found || val != "sk-bf-user-123" {
		t.Fatalf("want (sk-bf-user-123,true,nil) got (%q,%v,%v)", val, found, err)
	}
}

func TestResolveVKValue_UnknownEmail_NotFoundNoError(t *testing.T) {
	store := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{}}
	r := NewResolver(store, time.Minute)
	val, found, err := r.ResolveVKValue(context.Background(), "nobody@aquadoor.dev")
	if err != nil || found || val != "" {
		t.Fatalf("want ('',false,nil) got (%q,%v,%v)", val, found, err)
	}
}

func TestResolveVKValue_CacheHit_DoesNotRequery(t *testing.T) {
	store := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{
		"user@aquadoor.dev": vk("user@aquadoor.dev", "sk-bf-user-123"),
	}}
	r := NewResolver(store, time.Minute)
	for i := 0; i < 5; i++ {
		if _, found, _ := r.ResolveVKValue(context.Background(), "user@aquadoor.dev"); !found {
			t.Fatalf("call %d: expected found", i)
		}
	}
	if store.calls != 1 {
		t.Fatalf("expected 1 store call (cached), got %d", store.calls)
	}
}

func TestResolveVKValue_TTLExpiry_Requeries(t *testing.T) {
	store := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{
		"user@aquadoor.dev": vk("user@aquadoor.dev", "sk-bf-user-123"),
	}}
	base := time.Unix(1_000_000, 0)
	clock := base
	r := NewResolver(store, 30*time.Second)
	r.now = func() time.Time { return clock }

	_, _, _ = r.ResolveVKValue(context.Background(), "user@aquadoor.dev") // miss → 1 call, cached until +30s
	clock = base.Add(20 * time.Second)                                   // still fresh
	_, _, _ = r.ResolveVKValue(context.Background(), "user@aquadoor.dev")
	if store.calls != 1 {
		t.Fatalf("within TTL: expected 1 call, got %d", store.calls)
	}
	clock = base.Add(31 * time.Second) // expired
	_, _, _ = r.ResolveVKValue(context.Background(), "user@aquadoor.dev")
	if store.calls != 2 {
		t.Fatalf("after TTL: expected 2 calls, got %d", store.calls)
	}
}

func TestResolveVKValue_StoreError_Propagates_NotCached(t *testing.T) {
	store := &fakeStore{err: errors.New("db down")}
	r := NewResolver(store, time.Minute)
	_, found, err := r.ResolveVKValue(context.Background(), "user@aquadoor.dev")
	if err == nil || found {
		t.Fatalf("want (found=false, err!=nil) got (found=%v, err=%v)", found, err)
	}
	// A store error must NOT be cached — a retry must hit the store again.
	_, _, _ = r.ResolveVKValue(context.Background(), "user@aquadoor.dev")
	if store.calls != 2 {
		t.Fatalf("store error must not be cached; expected 2 calls, got %d", store.calls)
	}
}

func TestResolveVKValue_EmptyValue_TreatedAsMiss(t *testing.T) {
	store := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{
		"user@aquadoor.dev": vk("user@aquadoor.dev", ""), // VK row with no resolvable secret
	}}
	r := NewResolver(store, time.Minute)
	val, found, err := r.ResolveVKValue(context.Background(), "user@aquadoor.dev")
	if err != nil || found || val != "" {
		t.Fatalf("want ('',false,nil) got (%q,%v,%v)", val, found, err)
	}
}

func TestResolveVKValue_EmptyEmail_Miss(t *testing.T) {
	store := &fakeStore{vks: map[string]*configstoreTables.TableVirtualKey{}}
	r := NewResolver(store, time.Minute)
	_, found, err := r.ResolveVKValue(context.Background(), "   ")
	if err != nil || found {
		t.Fatalf("empty email should be a clean miss; got (found=%v, err=%v)", found, err)
	}
	if store.calls != 0 {
		t.Fatalf("empty email must not hit the store; got %d calls", store.calls)
	}
}
