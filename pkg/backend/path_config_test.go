package backend_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigReadWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithVersion(2)))

	storage := &logical.InmemStorage{}

	b := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

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

func TestConfigAuthCodeURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory())

	storage := &logical.InmemStorage{}

	b := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":       "abc",
			"client_secret":   "def",
			"provider":        "mock",
			"auth_url_params": map[string]string{"foo": "geoff"},
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Retrieve an auth code URL.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigAuthCodeURLPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"state":           "qwerty",
			"scopes":          []string{"read", "write"},
			"redirect_url":    "http://example.com/redirect",
			"auth_url_params": map[string]string{"foo": "bar", "baz": "quux"},
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.NotPanics(t, func() { _ = resp.Data["url"].(string) }, "response `url` field is not a string")

	u, err := url.Parse(resp.Data["url"].(string))
	require.NoError(t, err)

	qs := u.Query()
	u.RawQuery = ""
	u.Fragment = ""

	assert.Equal(t, testutil.MockAuthCodeURL, u.String())
	assert.Equal(t, "code", qs.Get("response_type"))
	assert.Equal(t, "abc", qs.Get("client_id"))
	assert.Equal(t, "qwerty", qs.Get("state"))
	assert.Equal(t, "read write", qs.Get("scope"))
	assert.Equal(t, "http://example.com/redirect", qs.Get("redirect_uri"))
	assert.Equal(t, "geoff", qs.Get("foo")) // Configuration takes precedence!
	assert.Equal(t, "quux", qs.Get("baz"))
}

func TestConfigClientCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage := &logical.InmemStorage{}

	b := backend.New(backend.Options{})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "abc",
			"client_secret": "def",
			"provider":      "custom",
			"provider_options": map[string]interface{}{
				"token_url": "http://localhost/auth/token",
			},
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Retrieve an auth code URL.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigAuthCodeURLPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"state":           "qwerty",
			"scopes":          []string{"read", "write"},
			"redirect_url":    "http://example.com/redirect",
			"auth_url_params": map[string]string{"foo": "bar", "baz": "quux"},
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.EqualError(t, resp.Error(), "authorization code URL not available")
}
