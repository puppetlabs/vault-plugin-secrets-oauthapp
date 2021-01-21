package backend

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestBasicAuthCodeExchange(t *testing.T) {
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
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, testutil.StaticMockAuthCodeExchange(token))))

	storage := &logical.InmemStorage{}

	b := New(Options{ProviderRegistry: pr})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
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
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"code": "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read the corresponding access token.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + `test`,
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

func TestInvalidAuthCodeExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	exchange := testutil.RestrictMockAuthCodeExchange(map[string]testutil.MockAuthCodeExchangeFunc{
		"valid": testutil.RandomMockAuthCodeExchange,
	})

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, exchange)))

	storage := &logical.InmemStorage{}

	b := New(Options{ProviderRegistry: pr})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
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

	// Write an invalid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"code": "invalid",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "exchange failed: oauth2: cannot fetch token: Forbidden\nResponse: ")
}

func TestRefreshableAuthCodeExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	refresh := func(i int) (time.Duration, error) {
		switch i {
		case 1:
			// Start with a short duration, which will force a refresh within
			// the library's grace period (< 10 seconds to expiry).
			return 2 * time.Second, nil
		default:
			return 10 * time.Minute, nil
		}
	}

	exchange := testutil.RefreshableMockAuthCodeExchange(testutil.IncrementMockAuthCodeExchange("token_"), refresh)

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, exchange)))

	storage := &logical.InmemStorage{}

	b := New(Options{ProviderRegistry: pr})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
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
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"code": "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read the corresponding access token. This should force a refresh, meaning
	// that our token value will be "token_2" (rather than the initial value of
	// "token_1").
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "token_2", resp.Data["access_token"])
	require.Equal(t, "Bearer", resp.Data["type"])
	require.NotEmpty(t, resp.Data["expire_time"])
}

func TestRefreshFailureReturnsNotConfigured(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	refresh := func(i int) (time.Duration, error) {
		switch i {
		case 1:
			// Start with a short duration, which will force a refresh within
			// the library's grace period (< 10 seconds to expiry).
			return 2 * time.Second, nil
		default:
			// Now we'll force a refresh failure.
			return 0, fmt.Errorf("you are not welcome")
		}
	}

	exchange := testutil.RefreshableMockAuthCodeExchange(testutil.IncrementMockAuthCodeExchange("token_"), refresh)

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, exchange)))

	storage := &logical.InmemStorage{}

	b := New(Options{ProviderRegistry: pr})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
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
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"code": "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Read the corresponding access token. This should force a refresh, which
	// should now return an invalidation from the server.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "token expired")
}

func TestScopesAndAudienceRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "hij",
		Secret: "def",
	}

	storage := &logical.InmemStorage{}

	b := New(Options{ProviderRegistry: provider.GlobalRegistry})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	tp := testutil.NewMockTokenProvider()
	defer tp.Close()

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"provider":      "custom",
			"provider_options": map[string]string{
				"auth_code_url": "not-used",
				"token_url":     tp.GetServerURL() + "/token",
			},
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write a valid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"refresh_token": "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.NotNil(t, resp.Data["access_token"])
	v, err := url.ParseQuery(resp.Data["access_token"].(string))
	require.NoError(t, err)
	default_scopes := v["scopes"]
	require.NotNil(t, default_scopes)
	default_audience := v["audience"]
	require.NotNil(t, default_audience)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"scopes": "scopea,scopec",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.NotNil(t, resp.Data["access_token"])
	v, err = url.ParseQuery(resp.Data["access_token"].(string))
	require.NoError(t, err)
	require.Equal(t, []string{"scopea scopec"}, v["scopes"])
	require.Equal(t, default_audience, v["audience"])

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"audience": "specific",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.NotNil(t, resp.Data["access_token"])
	v, err = url.ParseQuery(resp.Data["access_token"].(string))
	require.NoError(t, err)
	require.Equal(t, default_scopes, v["scopes"])
	require.Equal(t, []string{"specific"}, v["audience"])
}
