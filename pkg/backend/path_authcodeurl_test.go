package backend_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthCodeURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory())

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
		Path:      backend.AuthCodeURLPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"server":          "mock",
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
