package cache

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/golang-lru/simplelru"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
)

type AuthServerCacheEntry struct {
	*persistence.AuthServerEntry
	Provider provider.Provider
	users    int64
	cancel   context.CancelFunc
}

func (asce *AuthServerCacheEntry) Put() {
	atomic.AddInt64(&asce.users, -1)
}

func (asce *AuthServerCacheEntry) evict() {
	// Likely case: this entry is not being used, just evict it immediately.
	if atomic.CompareAndSwapInt64(&asce.users, 0, -1) {
		asce.cancel()
		return
	}

	// Otherwise, it's in use. Defer final cleanup until last user leaves. Since
	// it's evicted, this value will only decrease.
	go func() {
		for !atomic.CompareAndSwapInt64(&asce.users, 0, -1) {
			runtime.Gosched()
		}

		asce.cancel()
	}()
}

type AuthServerCache struct {
	providerRegistry *provider.Registry
	data             *persistence.AuthServerHolder

	mut     sync.RWMutex
	entries *simplelru.LRU
}

func (asc *AuthServerCache) Get(ctx context.Context, storage logical.Storage, keyer persistence.AuthServerKeyer) (entry *AuthServerCacheEntry, err error) {
	err = asc.data.WithLock(keyer, func(lash *persistence.LockedAuthServerHolder) (err error) {
		if value, found := asc.entries.Get(keyer.AuthServerKey()); found {
			entry = value.(*AuthServerCacheEntry)

			for {
				users := atomic.LoadInt64(&entry.users)

				// Make sure we're not currently evicting.
				if users < 0 {
					break
				}

				// Possible concurrent Put().
				if atomic.CompareAndSwapInt64(&entry.users, users, users+1) {
					return nil
				}
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			if err != nil {
				cancel()
			}
		}()

		// Need to read from storage to construct a new cache entry.
		delegate, err := lash.Manager(storage).ReadAuthServerEntry(ctx)
		if err != nil || delegate == nil {
			return err
		}

		p, err := asc.providerRegistry.NewAt(ctx, delegate.ProviderName, delegate.ProviderVersion, delegate.ProviderOptions)
		if err != nil {
			return err
		}

		entry = &AuthServerCacheEntry{
			AuthServerEntry: delegate,
			Provider:        p,
			users:           1,
			cancel:          cancel,
		}

		asc.mut.Lock()
		defer asc.mut.Unlock()

		asc.entries.Add(keyer.AuthServerKey(), entry)
		return nil
	})
	return
}

func (asc *AuthServerCache) Invalidate(keyer persistence.AuthServerKeyer) (found bool) {
	_ = asc.data.WithLock(keyer, func(_ *persistence.LockedAuthServerHolder) error {
		asc.mut.Lock()
		defer asc.mut.Unlock()

		found = asc.entries.Remove(keyer.AuthServerKey())
		return nil
	})
	return
}

func (asc *AuthServerCache) InvalidateFromStorage(key string) bool {
	keyer, ok := persistence.AuthServerKeyFromStorage(key)
	if !ok {
		return false
	}

	return asc.Invalidate(keyer)
}

func (asc *AuthServerCache) Purge() {
	keys := func() []interface{} {
		asc.mut.RLock()
		defer asc.mut.RUnlock()

		return asc.entries.Keys()
	}()

	for _, key := range keys {
		asc.InvalidateFromStorage(key.(string))
	}
}

func NewAuthServerCache(size int, providerRegistry *provider.Registry, data *persistence.AuthServerHolder) (*AuthServerCache, error) {
	lru, err := simplelru.NewLRU(size, func(_, value interface{}) {
		value.(*AuthServerCacheEntry).evict()
	})
	if err != nil {
		return nil, err
	}

	return &AuthServerCache{
		providerRegistry: providerRegistry,
		data:             data,

		entries: lru,
	}, nil
}
