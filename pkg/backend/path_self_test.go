package backend_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestBasicClientCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	token := &provider.Token{
		Token: &oauth2.Token{
			AccessToken: "valid",
		},
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithClientCredentials(client, testutil.StaticMockClientCredentials(token))))

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

	// Read the credential.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.SelfPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, token.AccessToken, resp.Data["access_token"])
	require.Equal(t, "Bearer", resp.Data["type"])
	require.Empty(t, resp.Data["expire_time"])
}

func TestConfiguredClientCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	handler := func(opts *provider.ClientCredentialsOptions) (*provider.Token, error) {
		return &provider.Token{
			Token: &oauth2.Token{
				AccessToken: fmt.Sprintf("%s:%s:%s", strings.Join(opts.Scopes, "."), opts.EndpointParams.Get("baz"), opts.ProviderOptions["tenant"]),
			},
		}, nil
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithClientCredentials(client, handler)))

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

	// Write credential configuration.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigSelfPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"scopes": []interface{}{"foo", "bar"},
			"token_url_params": map[string]interface{}{
				"baz": "quux",
			},
			"provider_options": map[string]interface{}{
				"tenant": "test",
			},
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read the credential.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.SelfPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "foo.bar:quux:test", resp.Data["access_token"])
	require.Equal(t, "Bearer", resp.Data["type"])
	require.Empty(t, resp.Data["expire_time"])
}

func TestExpiredClientCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	var handled bool
	handler := testutil.AmendTokenMockClientCredentials(testutil.IncrementMockClientCredentials("token_"), func(t *provider.Token) error {
		switch handled {
		case true:
			t.Expiry = time.Now().Add(10 * time.Minute)
		default:
			t.Expiry = time.Now().Add(2 * time.Second)
			handled = true
		}
		return nil
	})

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithClientCredentials(client, handler)))

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

	// Write credential configuration.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigSelfPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"scopes": []interface{}{"foo", "bar"},
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read the credential. Because our initial expiry is so small, this should
	// force the token to update.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.SelfPathPrefix + `test`,
		Storage:   storage,
	}

	// We do two reads to ensure the token stays the same once it has a longer
	// expiration.
	for i := 0; i < 2; i++ {
		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
		require.Equal(t, "token_2", resp.Data["access_token"])
		require.Equal(t, "Bearer", resp.Data["type"])
		require.NotEmpty(t, resp.Data["expire_time"])
	}
}
