package provider_test

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var basicTestFactory = provider.BasicFactory(provider.Endpoint{
	Endpoint: oauth2.Endpoint{
		AuthURL:   "http://localhost/authorize",
		TokenURL:  "http://localhost/token",
		AuthStyle: oauth2.AuthStyleInParams,
	},
})

func TestBasicPublic(t *testing.T) {
	ctx := context.Background()

	r := provider.NewRegistry()
	r.MustRegister("basic", basicTestFactory)

	basicTest, err := r.New(ctx, "basic", map[string]string{})
	require.NoError(t, err)

	ops := basicTest.Public("foo")

	authCodeURL, ok := ops.AuthCodeURL(
		"state",
		provider.WithRedirectURL("http://example.com/redirect"),
		provider.WithScopes{"a", "b", "c"},
		provider.WithURLParams{"baz": "quux"},
	)
	require.True(t, ok)

	u, err := url.Parse(authCodeURL)
	require.NoError(t, err)

	assert.Equal(t, "http", u.Scheme)
	assert.Equal(t, "localhost", u.Host)
	assert.Equal(t, "/authorize", u.Path)

	qs := u.Query()
	assert.Equal(t, "code", qs.Get("response_type"))
	assert.Equal(t, "foo", qs.Get("client_id"))
	assert.Equal(t, "http://example.com/redirect", qs.Get("redirect_uri"))
	assert.Equal(t, "state", qs.Get("state"))
	assert.Equal(t, "a b c", qs.Get("scope"))
	assert.Equal(t, "quux", qs.Get("baz"))
}

func TestBasicPrivate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r := provider.NewRegistry()
	r.MustRegister("basic", basicTestFactory)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			b, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)

			data, err := url.ParseQuery(string(b))
			require.NoError(t, err)

			assert.Equal(t, "foo", data.Get("client_id"))
			assert.Equal(t, "bar", data.Get("client_secret"))

			switch data.Get("grant_type") {
			case "authorization_code":
				assert.Equal(t, "authorization_code", data.Get("grant_type"))
				assert.Equal(t, "123456", data.Get("code"))
				assert.Equal(t, "http://example.com/redirect", data.Get("redirect_uri"))
				assert.Equal(t, "quux", data.Get("baz"))

				_, _ = w.Write([]byte(`access_token=abcd&refresh_token=efgh&token_type=bearer&expires_in=60`))
			case "refresh_token":
				assert.Equal(t, "efgh", data.Get("refresh_token"))

				_, _ = w.Write([]byte(`access_token=ijkl&refresh_token=efgh&token_type=bearer&expires_in=3600`))
			case "client_credentials":
				_, _ = w.Write([]byte(`access_token=mnop&token_type=bearer&expires_in=86400`))
			default:
				assert.Fail(t, "unexpected `grant_type` value: %q", data.Get("grant_type"))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c := &http.Client{Transport: &testutil.MockRoundTripper{Handler: h}}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c)

	basicTest, err := r.New(ctx, "basic", map[string]string{})
	require.NoError(t, err)

	ops := basicTest.Private("foo", "bar")

	token, err := ops.AuthCodeExchange(
		ctx,
		"123456",
		provider.WithURLParams{"baz": "quux"},
		provider.WithRedirectURL("http://example.com/redirect"),
	)
	require.NoError(t, err)
	require.NotNil(t, token)
	require.True(t, token.Valid())
	require.Equal(t, "abcd", token.AccessToken)
	require.Equal(t, "Bearer", token.Type())
	require.Equal(t, "efgh", token.RefreshToken)
	require.NotEmpty(t, token.Expiry)

	token, err = ops.RefreshToken(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, token)

	// Our refreshed response is good for an hour.
	require.Equal(t, "ijkl", token.AccessToken)
	require.True(t, token.Valid())

	token, err = ops.ClientCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, token)
	require.Equal(t, "mnop", token.AccessToken)
	require.True(t, token.Valid())
}
