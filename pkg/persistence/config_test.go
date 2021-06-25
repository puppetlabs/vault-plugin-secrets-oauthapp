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

	require.NoError(t, cm.WriteConfig(ctx, &persistence.ConfigEntry{
		Version: persistence.ConfigVersion1,
		Tuning: persistence.ConfigTuningEntry{
			RefreshCheckIntervalSeconds: 300,
		},
	}))

	entry, err = cm.ReadConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, 300, entry.Tuning.RefreshCheckIntervalSeconds)
}
