package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimitedExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "hij",
		Secret: "def",
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(
		testutil.MockWithAuthCodeExchange(client, testutil.IncrementMockAuthCodeExchange("token_")),
		testutil.MockWithTokenExchange(client, testutil.RestrictMockTokenExchange(map[string]testutil.MockTokenExchangeFunc{
			"token_1": testutil.FilterMockTokenExchange(
				testutil.ExpiringMockTokenExchange(testutil.IncrementMockTokenExchange("limited_"), 2*time.Minute),
				func(_ *provider.Token, opts *provider.TokenExchangeOptions) bool {
					return assert.Equal(t, []string{"scopea", "scopec"}, opts.Scopes)
				},
				func(_ *provider.Token, opts *provider.TokenExchangeOptions) bool {
					return assert.Equal(t, []string{"urn:audiencea", "urn:audiencec"}, opts.Audiences)
				},
				func(_ *provider.Token, opts *provider.TokenExchangeOptions) bool {
					return assert.Equal(t, []string{"urn:resourcea", "urn:resourcec"}, opts.Resources)
				},
			),
		})),
	))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{StorageView: storage}))

	// Write server configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"provider":      "mock",
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write a valid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"server": "mock",
			"code":   "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read a limited credential.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.STSPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"scopes":    "scopea,scopec",
			"audiences": "urn:audiencea,urn:audiencec",
			"resources": "urn:resourcea,urn:resourcec",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "limited_1", resp.Data["access_token"])
	require.Equal(t, "Bearer", resp.Data["type"])
	require.NotEmpty(t, resp.Data["expire_time"])
}
