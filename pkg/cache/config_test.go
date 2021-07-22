package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/cache"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/stretchr/testify/require"
)

func TestConfigCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage := &logical.InmemStorage{}
	h := persistence.NewHolder()
	cc := cache.NewConfigCache(h.Config)

	// Get from cache. No stored config should return nil.
	missing, err := cc.Get(ctx, storage)
	require.NoError(t, err)
	require.Nil(t, missing)

	// Write a configuration.
	initialConfig := &persistence.ConfigEntry{
		Version: persistence.ConfigVersionLatest,
		Tuning: persistence.ConfigTuningEntry{
			ProviderTimeoutSeconds: 42,
		},
	}
	require.NoError(t, h.Config.Manager(storage).WriteConfig(ctx, initialConfig))

	// Get again from cache. This should return the actual stored configuration.
	initial, err := cc.Get(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, initial)
	require.Equal(t, initialConfig, initial.ConfigEntry)

	// Write a new configuration.
	updatedConfig := &persistence.ConfigEntry{
		Version: persistence.ConfigVersionLatest,
		Tuning:  persistence.DefaultConfigTuningEntry,
	}
	require.NotEqual(t, updatedConfig, initialConfig) // Sanity check.
	require.NoError(t, h.Config.Manager(storage).WriteConfig(ctx, updatedConfig))

	// Get from cache. This should return a stale entry.
	stale, err := cc.Get(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, stale)
	require.Equal(t, initialConfig, stale.ConfigEntry)

	// Invalidate the cache, so the next read should return an updated entry.
	cc.Invalidate()

	// Check updated entry.
	updated, err := cc.Get(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.Equal(t, updatedConfig, updated.ConfigEntry)
}
