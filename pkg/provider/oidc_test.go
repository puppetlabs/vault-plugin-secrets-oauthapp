package provider_test

import (
	"context"
	"io"
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

const testOIDCConfiguration = `
{
	"issuer": "http://localhost",
	"authorization_endpoint": "http://localhost/authorize",
	"token_endpoint": "http://localhost/token",
	"userinfo_endpoint": "http://localhost/userinfo",
	"jwks_uri": "http://localhost/.well-known/jwks.json",
	"response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
	"id_token_signing_alg_values_supported": ["RS256"],
	"token_endpoint_auth_methods_supported": ["client_secret_post"]
}
`

func TestOIDCFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			io.WriteString(w, testOIDCConfiguration)
		case "/.well-known/jwks.json":
			w.WriteHeader(http.StatusInternalServerError)
		case "/token":
			b, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)

			data, err := url.ParseQuery(string(b))
			require.NoError(t, err)

			assert.Equal(t, "authorization_code", data.Get("grant_type"))
			assert.Equal(t, "foo", data.Get("client_id"))
			assert.Equal(t, "bar", data.Get("client_secret"))

			w.Write([]byte(`access_token=abcd&refresh_token=efgh&token_type=bearer&expires_in=5`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c := &http.Client{Transport: &testutil.MockRoundTripper{Handler: h}}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c)

	oidcTest, err := provider.GlobalRegistry.New(ctx, "oidc", map[string]string{
		"issuer_url":        "http://localhost",
		"extra_data_fields": "id_token,id_token_claims,user_info",
	})
	require.NoError(t, err)

	conf := oidcTest.NewExchangeConfigBuilder("foo", "bar").
		WithOption("nonce", "baz").
		WithRedirectURL("http://example.com/redirect").
		Build()

	token, err := conf.Exchange(ctx, "123456", oauth2.SetAuthURLParam("baz", "quux"))
	require.NoError(t, err)
	require.NotNil(t, token)
}
