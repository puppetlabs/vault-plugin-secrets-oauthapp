package cache

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
)

type ConfigCacheEntry struct {
	*persistence.ConfigEntry
}

type ConfigCache struct {
	data *persistence.ConfigHolder

	entry *ConfigCacheEntry
}

func (cc *ConfigCache) Get(ctx context.Context, storage logical.Storage) (entry *ConfigCacheEntry, err error) {
	err = cc.data.WithLock(func(lch *persistence.LockedConfigHolder) error {
		entry = cc.entry
		if entry != nil {
			return nil
		}

		delegate, err := lch.Manager(storage).ReadConfig(ctx)
		if err != nil || delegate == nil {
			return err
		}

		entry = &ConfigCacheEntry{
			ConfigEntry: delegate,
		}

		cc.entry = entry
		return nil
	})
	return
}

func (cc *ConfigCache) Invalidate() (found bool) {
	_ = cc.data.WithLock(func(lch *persistence.LockedConfigHolder) error {
		found = cc.entry != nil
		cc.entry = nil
		return nil
	})
	return
}

func (cc *ConfigCache) InvalidateFromStorage(key string) bool {
	if !persistence.IsConfigKey(key) {
		return false
	}

	return cc.Invalidate()
}

func (cc *ConfigCache) Purge() {
	cc.Invalidate()
}

func NewConfigCache(data *persistence.ConfigHolder) *ConfigCache {
	return &ConfigCache{
		data: data,
	}
}
