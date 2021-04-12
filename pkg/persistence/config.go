package persistence

import (
	"context"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configKey = "config"
)

type ConfigTuning struct {
	RefreshCheckIntervalSeconds int `json:"refresh_check_interval_seconds"`
}

type ConfigEntry struct {
	ClientID        string            `json:"client_id"`
	ClientSecret    string            `json:"client_secret"`
	AuthURLParams   map[string]string `json:"auth_url_params"`
	ProviderName    string            `json:"provider_name"`
	ProviderVersion int               `json:"provider_version"`
	ProviderOptions map[string]string `json:"provider_options"`
	Tuning          ConfigTuning      `json:"tuning"`
}

type LockedConfigManager struct {
	storage logical.Storage
}

func (lcm *LockedConfigManager) ReadConfig(ctx context.Context) (*ConfigEntry, error) {
	se, err := lcm.storage.Get(ctx, configKey)
	if err != nil {
		return nil, err
	} else if se == nil {
		return nil, nil
	}

	entry := &ConfigEntry{}
	if err := se.DecodeJSON(entry); err != nil {
		return nil, err
	}

	return entry, nil
}

func (lcm *LockedConfigManager) WriteConfig(ctx context.Context, entry *ConfigEntry) error {
	se, err := logical.StorageEntryJSON(configKey, entry)
	if err != nil {
		return err
	}

	return lcm.storage.Put(ctx, se)
}

func (lcm *LockedConfigManager) DeleteConfig(ctx context.Context) error {
	return lcm.storage.Delete(ctx, configKey)
}

type ConfigManager struct {
	storage logical.Storage
	locks   []*locksutil.LockEntry
}

func (cm *ConfigManager) WithLock(fn func(*LockedConfigManager) error) error {
	lock := locksutil.LockForKey(cm.locks, configKey)
	lock.Lock()
	defer lock.Unlock()

	return fn(&LockedConfigManager{
		storage: cm.storage,
	})
}

func (cm *ConfigManager) ReadConfig(ctx context.Context) (*ConfigEntry, error) {
	var entry *ConfigEntry
	err := cm.WithLock(func(lcm *LockedConfigManager) (err error) {
		entry, err = lcm.ReadConfig(ctx)
		return
	})
	return entry, err
}

func (cm *ConfigManager) WriteConfig(ctx context.Context, entry *ConfigEntry) error {
	return cm.WithLock(func(lcm *LockedConfigManager) error {
		return lcm.WriteConfig(ctx, entry)
	})
}

func (cm *ConfigManager) DeleteConfig(ctx context.Context) error {
	return cm.WithLock(func(lcm *LockedConfigManager) error {
		return lcm.DeleteConfig(ctx)
	})
}

func IsConfigKey(key string) bool {
	return key == configKey
}
