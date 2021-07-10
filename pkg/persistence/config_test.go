package persistence_test

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/stretchr/testify/require"
)

func TestConfigVersionInitial(t *testing.T) {
	ctx := context.Background()
	cm := persistence.NewHolder().Managers(&logical.InmemStorage{}).Config()

	require.NoError(t, cm.WriteConfig(ctx, &persistence.ConfigEntry{
		Version: persistence.ConfigVersionInitial,
	}))

	entry, err := cm.ReadConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, persistence.DefaultConfigTuningEntry.RefreshCheckIntervalSeconds, entry.Tuning.RefreshCheckIntervalSeconds)
	require.Equal(t, persistence.DefaultConfigTuningEntry.RefreshExpiryDeltaFactor, entry.Tuning.RefreshExpiryDeltaFactor)
	require.Equal(t, 0, entry.Tuning.ReapCheckIntervalSeconds)
}

func TestConfigVersion1(t *testing.T) {
	ctx := context.Background()
	cm := persistence.NewHolder().Managers(&logical.InmemStorage{}).Config()

	require.NoError(t, cm.WriteConfig(ctx, &persistence.ConfigEntry{
		Version: persistence.ConfigVersion1,
	}))

	entry, err := cm.ReadConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, entry.Tuning.RefreshCheckIntervalSeconds)
	require.Equal(t, persistence.DefaultConfigTuningEntry.RefreshExpiryDeltaFactor, entry.Tuning.RefreshExpiryDeltaFactor)
	require.Equal(t, 0, entry.Tuning.ReapCheckIntervalSeconds)

	require.NoError(t, cm.WriteConfig(ctx, &persistence.ConfigEntry{
		Version: persistence.ConfigVersion1,
		Tuning: persistence.ConfigTuningEntry{
			RefreshCheckIntervalSeconds: 300,
		},
	}))

	entry, err = cm.ReadConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, 300, entry.Tuning.RefreshCheckIntervalSeconds)
	require.Equal(t, persistence.DefaultConfigTuningEntry.RefreshExpiryDeltaFactor, entry.Tuning.RefreshExpiryDeltaFactor)
	require.Equal(t, 0, entry.Tuning.ReapCheckIntervalSeconds)
}

func TestConfigVersion2(t *testing.T) {
	ctx := context.Background()
	cm := persistence.NewHolder().Managers(&logical.InmemStorage{}).Config()

	require.NoError(t, cm.WriteConfig(ctx, &persistence.ConfigEntry{
		Version: persistence.ConfigVersion2,
	}))

	entry, err := cm.ReadConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, entry.Tuning.RefreshCheckIntervalSeconds)
	require.Equal(t, 0.0, entry.Tuning.RefreshExpiryDeltaFactor)
	require.Equal(t, 0, entry.Tuning.ReapCheckIntervalSeconds)

	require.NoError(t, cm.WriteConfig(ctx, &persistence.ConfigEntry{
		Version: persistence.ConfigVersion2,
		Tuning: persistence.ConfigTuningEntry{
			RefreshCheckIntervalSeconds: 300,
			RefreshExpiryDeltaFactor:    2,
			ReapCheckIntervalSeconds:    180,
		},
	}))

	entry, err = cm.ReadConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, 300, entry.Tuning.RefreshCheckIntervalSeconds)
	require.Equal(t, 2.0, entry.Tuning.RefreshExpiryDeltaFactor)
	require.Equal(t, 180, entry.Tuning.ReapCheckIntervalSeconds)
}
