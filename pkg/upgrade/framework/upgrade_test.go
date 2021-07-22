package framework_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/upgrade/framework"
	"github.com/stretchr/testify/require"
)

type noOpUpgrader struct{}

func (*noOpUpgrader) SentinelKey() string               { return "noop" }
func (*noOpUpgrader) Upgrade(ctx context.Context) error { return nil }

func noOpFactory(*persistence.Holder, logical.Storage) framework.Upgrader {
	return &noOpUpgrader{}
}

type counterUpgrader struct {
	invocations *int
}

func (*counterUpgrader) SentinelKey() string { return "counter" }
func (cu *counterUpgrader) Upgrade(ctx context.Context) error {
	(*cu.invocations)++
	return nil
}

func counterFactory(invocations *int) framework.UpgraderFactoryFunc {
	return func(*persistence.Holder, logical.Storage) framework.Upgrader {
		return &counterUpgrader{
			invocations: invocations,
		}
	}
}

func TestUpgradeReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data := persistence.NewHolder()
	storage := &logical.InmemStorage{}

	factories := []framework.UpgraderFactoryFunc{
		noOpFactory,
	}

	// Do the actual upgrade in a Goroutine.
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		require.NoError(t, framework.Upgrade(ctx, factories, data, storage, false))
	}()

	// Wait for the sentinel to be set.
	require.NoError(t, framework.Upgrade(ctx, factories, data, storage, true))
}

func TestUpgradeSentinels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	data := persistence.NewHolder()
	storage := &logical.InmemStorage{}

	var invocations int
	factories := []framework.UpgraderFactoryFunc{
		counterFactory(&invocations),
	}

	require.NoError(t, framework.Upgrade(ctx, factories, data, storage, false))
	require.Equal(t, invocations, 1)

	// Should not be called again when upgrading if the sentinel is in place.
	require.NoError(t, framework.Upgrade(ctx, factories, data, storage, false))
	require.Equal(t, invocations, 1)
}
