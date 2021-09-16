package cache_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/cache"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestAuthServerCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage := &logical.InmemStorage{}
	h := persistence.NewHolder()

	// Write server configurations.
	namer := func(i int) string {
		return fmt.Sprintf("server-%d", i)
	}

	keyer := func(i int) persistence.AuthServerKeyer {
		return persistence.AuthServerName(namer(i))
	}

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	ch := make(chan string)

	delegate := testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, testutil.RandomMockAuthCodeExchange))
	reporter := func(cctx context.Context, vsn int, options map[string]string) (provider.Provider, error) {
		server := options["server"]
		delete(options, "server")

		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case <-cctx.Done():
			case <-ctx.Done():
				require.Fail(t, "context expired waiting for eviction", "server %s", server)
			}

			select {
			case ch <- server:
			case <-ctx.Done():
				require.Fail(t, "context expired waiting to write eviction to channel", "server %s", server)
			}
		}()

		return delegate(cctx, vsn, options)
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", reporter)

	for i := 0; i < 4; i++ {
		entry := &persistence.AuthServerEntry{
			Name: namer(i),

			ClientID:        client.ID,
			ClientSecret:    client.Secret,
			ProviderName:    "mock",
			ProviderVersion: provider.VersionLatest,
			ProviderOptions: map[string]string{
				"server": fmt.Sprintf("server-%d", i),
			},
		}

		require.NoError(t, h.AuthServer.Manager(storage).WriteAuthServerEntry(ctx, persistence.AuthServerName(entry.Name), entry))
	}

	asc, err := cache.NewAuthServerCache(2, pr, h.AuthServer)
	require.NoError(t, err)

	// Populate the cache.
	servers := make([]*cache.AuthServerCacheEntry, 2)

	for i := 0; i < 2; i++ {
		server, err := asc.Get(ctx, storage, keyer(i))
		require.NoError(t, err)
		require.NotNil(t, server)

		// Store the server for future Put().
		servers[i] = server
	}

	// Return second server to cache. This will make it the first to be
	// cancelled on eviction despite being the second evicted.
	servers[1].Put()

	// Force cache evictions by asking for the remaining servers.
	for i := 2; i < 4; i++ {
		server, err := asc.Get(ctx, storage, keyer(i))
		require.NoError(t, err)
		require.NotNil(t, server)

		server.Put()
	}

	// First value on channel should be the second server.
	select {
	case server := <-ch:
		require.Equal(t, "server-1", server)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for second server to be evicted from cache")
	}

	// Return the remaining server to the cache. This will cause its eviction to
	// finalize.
	servers[0].Put()

	// Second value on channel should be the first server now that it has no
	// users.
	select {
	case server := <-ch:
		require.Equal(t, "server-0", server)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for first server to be evicted from cache")
	}

	// Purge the cache to evict the remaining two servers. This should be in
	// order from least to most recently used.
	asc.Purge()

	// Remaining values may come in any order.
	for i := 0; i < 2; i++ {
		select {
		case server := <-ch:
			require.Contains(t, []string{"server-2", "server-3"}, server)
		case <-ctx.Done():
			require.Fail(t, "context expired waiting for remaining servers to be evicted from cache")
		}
	}
}
