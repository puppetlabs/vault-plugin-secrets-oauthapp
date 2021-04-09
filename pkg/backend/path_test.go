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
)

func TestAcceptableCredentialNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(
		testutil.MockWithAuthCodeExchange(client, testutil.RandomMockAuthCodeExchange),
		testutil.MockWithClientCredentials(client, testutil.RandomMockClientCredentials),
	))

	storage := &logical.InmemStorage{}

	b := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigPath,
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

	tests := []struct {
		Name       string
		Acceptable bool
	}{
		{
			Name:       "test",
			Acceptable: true,
		},
		{
			Name:       "foo/bar/baz",
			Acceptable: true,
		},
		{
			Name:       "test@REALM.EXAMPLE.COM",
			Acceptable: true,
		},
		{
			Name:       "test@REALM.EXAMPLE.COM:machine",
			Acceptable: true,
		},
		{
			Name:       "test@REALM.EXAMPLE.COM/sub",
			Acceptable: true,
		},
		{
			Name:       "foo/:/bar",
			Acceptable: false,
		},
		{
			Name:       "foo:/bar",
			Acceptable: false,
		},
		{
			Name:       "foo/bar:/baz",
			Acceptable: false,
		},
		{
			Name:       "foo/bar:",
			Acceptable: false,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			// Test for auth code exchange.
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      backend.CredsPathPrefix + test.Name,
				Storage:   storage,
				Data: map[string]interface{}{
					"code": "test",
				},
			}

			resp, err := b.HandleRequest(ctx, req)
			if !test.Acceptable {
				require.Equal(t, logical.ErrUnsupportedPath, err)
			} else {
				require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
				require.Nil(t, resp)
			}

			// Test for client credentials exchange.
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      backend.SelfPathPrefix + test.Name,
				Storage:   storage,
			}

			resp, err = b.HandleRequest(ctx, req)
			if !test.Acceptable {
				require.Equal(t, logical.ErrUnsupportedPath, err)
			} else {
				require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
				require.NotNil(t, resp)
				require.NotEmpty(t, resp.Data["access_token"])
			}
		})
	}
}
