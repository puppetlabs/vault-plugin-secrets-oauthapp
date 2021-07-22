package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestConfigReadWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithVersion(2)))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{StorageView: storage}))

	// Read configuration; we should be unconfigured at this point.
	read := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.ConfigPath,
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Write new configuration.
	write := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"tune_provider_timeout_seconds": 42,
		},
	}

	resp, err = b.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read new configuration.
	resp, err = b.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 42, resp.Data["tune_provider_timeout_seconds"])
	require.Equal(t, persistence.DefaultConfigTuningEntry.RefreshCheckIntervalSeconds, resp.Data["tune_refresh_check_interval_seconds"])
}
