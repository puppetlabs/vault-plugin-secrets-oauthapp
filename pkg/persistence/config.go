package persistence

import (
	"context"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configKey = "config"
)

func IsConfigKey(key string) bool {
	return key == configKey
}

type ConfigVersion int

const (
	ConfigVersionInitial ConfigVersion = iota
	ConfigVersion1
	ConfigVersion2
	ConfigVersion3
	ConfigVersionLatest = ConfigVersion3
)

func (cv ConfigVersion) SupportsTuningRefresh() bool {
	return cv >= ConfigVersion1
}

func (cv ConfigVersion) SupportsTuningRefreshExpiryDelta() bool {
	return cv >= ConfigVersion2
}

func (cv ConfigVersion) SupportsTuningProviderTimeout() bool {
	return cv >= ConfigVersion2
}

func (cv ConfigVersion) SupportsTuningReaper() bool {
	return cv >= ConfigVersion2
}

type ConfigTuningEntry struct {
	ProviderTimeoutSeconds            int     `json:"provider_timeout_seconds"`
	ProviderTimeoutExpiryLeewayFactor float64 `json:"provider_timeout_expiry_leeway_factor"`
	RefreshCheckIntervalSeconds       int     `json:"refresh_check_interval_seconds"`
	RefreshExpiryDeltaFactor          float64 `json:"refresh_expiry_delta_factor"`
	ReapCheckIntervalSeconds          int     `json:"reap_check_interval_seconds"`
	ReapDryRun                        bool    `json:"reap_dry_run"`
	ReapNonRefreshableSeconds         int     `json:"reap_non_refreshable_seconds"`
	ReapRevokedSeconds                int     `json:"reap_revoked_seconds"`
	ReapTransientErrorAttempts        int     `json:"reap_transient_error_attempts"`
	ReapTransientErrorSeconds         int     `json:"reap_transient_error_seconds"`
}

var DefaultConfigTuningEntry = ConfigTuningEntry{
	ProviderTimeoutSeconds:            30,
	ProviderTimeoutExpiryLeewayFactor: 1.5,
	RefreshCheckIntervalSeconds:       60,
	RefreshExpiryDeltaFactor:          1.2,
	ReapCheckIntervalSeconds:          300,
	ReapDryRun:                        false,
	ReapNonRefreshableSeconds:         86400,
	ReapRevokedSeconds:                3600,
	ReapTransientErrorAttempts:        10,
	ReapTransientErrorSeconds:         86400,
}

type ConfigEntry struct {
	Version       ConfigVersion     `json:"version"`
	DefaultServer string            `json:"default_server"`
	Tuning        ConfigTuningEntry `json:"tuning"`
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

	if !entry.Version.SupportsTuningRefresh() {
		entry.Tuning.RefreshCheckIntervalSeconds = DefaultConfigTuningEntry.RefreshCheckIntervalSeconds
	}

	if !entry.Version.SupportsTuningRefreshExpiryDelta() {
		entry.Tuning.RefreshExpiryDeltaFactor = DefaultConfigTuningEntry.RefreshExpiryDeltaFactor
	}

	if !entry.Version.SupportsTuningProviderTimeout() {
		entry.Tuning.ProviderTimeoutSeconds = DefaultConfigTuningEntry.ProviderTimeoutSeconds
		entry.Tuning.ProviderTimeoutExpiryLeewayFactor = DefaultConfigTuningEntry.ProviderTimeoutExpiryLeewayFactor
	}

	if !entry.Version.SupportsTuningReaper() {
		// Disable reaper (users must opt in by writing new configuration
		// version).
		entry.Tuning.ReapCheckIntervalSeconds = 0

		// We set the other values so users can see what they'll get by default
		// if they enable it.
		entry.Tuning.ReapDryRun = DefaultConfigTuningEntry.ReapDryRun
		entry.Tuning.ReapNonRefreshableSeconds = DefaultConfigTuningEntry.ReapNonRefreshableSeconds
		entry.Tuning.ReapRevokedSeconds = DefaultConfigTuningEntry.ReapRevokedSeconds
		entry.Tuning.ReapTransientErrorAttempts = DefaultConfigTuningEntry.ReapTransientErrorAttempts
		entry.Tuning.ReapTransientErrorSeconds = DefaultConfigTuningEntry.ReapTransientErrorSeconds
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

type LockedConfigHolder struct{}

func (lch *LockedConfigHolder) Manager(storage logical.Storage) *LockedConfigManager {
	return &LockedConfigManager{
		storage: storage,
	}
}

type ConfigLocker interface {
	WithLock(func(*LockedConfigHolder) error) error
}

type ConfigManager struct {
	storage logical.Storage
	locker  ConfigLocker
}

func (cm *ConfigManager) ReadConfig(ctx context.Context) (*ConfigEntry, error) {
	var entry *ConfigEntry
	err := cm.locker.WithLock(func(lch *LockedConfigHolder) (err error) {
		entry, err = lch.Manager(cm.storage).ReadConfig(ctx)
		return
	})
	return entry, err
}

func (cm *ConfigManager) WriteConfig(ctx context.Context, entry *ConfigEntry) error {
	return cm.locker.WithLock(func(lch *LockedConfigHolder) error {
		return lch.Manager(cm.storage).WriteConfig(ctx, entry)
	})
}

func (cm *ConfigManager) DeleteConfig(ctx context.Context) error {
	return cm.locker.WithLock(func(lch *LockedConfigHolder) error {
		return lch.Manager(cm.storage).DeleteConfig(ctx)
	})
}

type ConfigHolder struct {
	locks []*locksutil.LockEntry
}

func (ch *ConfigHolder) WithLock(fn func(*LockedConfigHolder) error) error {
	lock := locksutil.LockForKey(ch.locks, configKey)
	lock.Lock()
	defer lock.Unlock()

	return fn(&LockedConfigHolder{})
}

func (ch *ConfigHolder) Manager(storage logical.Storage) *ConfigManager {
	return &ConfigManager{
		storage: storage,
		locker:  ch,
	}
}
