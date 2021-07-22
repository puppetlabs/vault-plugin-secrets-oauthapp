package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestServerReadWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithVersion(2)))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Read configuration; we should be unconfigured at this point.
	read := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Write new configuration.
	write := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "abc",
			"client_secret": "def",
			"provider":      "mock",
		},
	}

	resp, err = b.HandleRequest(ctx, write)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read new configuration; ensure client secret is not present.
	resp, err = b.HandleRequest(ctx, read)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "abc", resp.Data["client_id"])
	require.Empty(t, resp.Data["client_secret"])
	require.Equal(t, "mock", resp.Data["provider"])
	require.Equal(t, 2, resp.Data["provider_version"])
}

func TestMultipleServers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	servers := []struct {
		Name   string
		Token  string
		Client testutil.MockClient
	}{
		{
			Name:  "server1",
			Token: "token1",
			Client: testutil.MockClient{
				ID:     "id1",
				Secret: "secret1",
			},
		},
		{
			Name:  "server2",
			Token: "token2",
			Client: testutil.MockClient{
				ID:     "id2",
				Secret: "secret2",
			},
		},
		{
			Name:  "server3",
			Token: "token3",
			Client: testutil.MockClient{
				ID:     "id3",
				Secret: "secret3",
			},
		},
	}

	// Generate mock factory options.
	var opts []testutil.MockOption
	for _, server := range servers {
		opts = append(opts, testutil.MockWithAuthCodeExchange(
			server.Client,
			testutil.StaticMockAuthCodeExchange(&provider.Token{
				Token: &oauth2.Token{
					AccessToken: server.Token,
				},
			}),
		))
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(opts...))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write server configurations and credentials.
	for _, server := range servers {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      backend.ServersPathPrefix + server.Name,
			Storage:   storage,
			Data: map[string]interface{}{
				"client_id":     server.Client.ID,
				"client_secret": server.Client.Secret,
				"provider":      "mock",
			},
		}

		resp, err := b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      backend.CredsPathPrefix + server.Name,
			Storage:   storage,
			Data: map[string]interface{}{
				"server": server.Name,
				"code":   "test",
			},
		}

		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)
	}

	// Now that all credentials are in place, make sure they contain the right
	// values.
	for _, server := range servers {
		t.Run(server.Name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      backend.CredsPathPrefix + server.Name,
				Storage:   storage,
			}

			resp, err := b.HandleRequest(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
			require.Equal(t, server.Token, resp.Data["access_token"])
			require.Equal(t, "Bearer", resp.Data["type"])
			require.Empty(t, resp.Data["expire_time"])
		})
	}
}
