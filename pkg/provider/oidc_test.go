package provider_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
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

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privateKey,
	}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = io.WriteString(w, testOIDCConfiguration)
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(&jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{
						Key:   &privateKey.PublicKey,
						KeyID: "key",
						Use:   "sig",
					},
				},
			})
		case "/token":
			b, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)

			data, err := url.ParseQuery(string(b))
			require.NoError(t, err)

			assert.Equal(t, "authorization_code", data.Get("grant_type"))
			assert.Equal(t, "foo", data.Get("client_id"))
			assert.Equal(t, "bar", data.Get("client_secret"))

			idClaims := jwt.Claims{
				Issuer:   "http://localhost",
				Audience: jwt.Audience{"foo"},
				Subject:  "test-user",
				Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}

			idToken, err := jwt.Signed(signer).
				Claims(idClaims).
				Claims(map[string]interface{}{"nonce": "baz"}).
				CompactSerialize()
			require.NoError(t, err)

			resp := make(url.Values)
			resp.Set("access_token", "abcd")
			resp.Set("refresh_token", "efgh")
			resp.Set("token_type", "bearer")
			resp.Set("id_token", idToken)
			resp.Set("expires_in", "900")

			_, _ = io.WriteString(w, resp.Encode())
		case "/userinfo":
			assert.Equal(t, "Bearer abcd", r.Header.Get("authorization"))

			_ = json.NewEncoder(w).Encode(oidc.UserInfo{
				Subject: "test-user",
				Profile: "https://example.com/test-user",
				Email:   "test-user@example.com",
			})
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

	ops := oidcTest.Private("foo", "bar")

	token, err := ops.AuthCodeExchange(
		ctx,
		"123456",
		provider.WithRedirectURL("http://example.com/redirect"),
		provider.WithProviderOptions{"nonce": "baz"},
		provider.WithURLParams{"baz": "quux"},
	)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "abcd", token.AccessToken)
	assert.Equal(t, "Bearer", token.Type())
	assert.Equal(t, "efgh", token.RefreshToken)
	assert.NotEmpty(t, token.Expiry)
	require.Contains(t, token.ExtraData, "id_token")
	require.Contains(t, token.ExtraData, "id_token_claims")
	require.Contains(t, token.ExtraData, "user_info")
	require.NotEmpty(t, token.ExtraData["id_token"])

	idTokenClaims, ok := token.ExtraData["id_token_claims"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "test-user", idTokenClaims["sub"])
	assert.Equal(t, "http://localhost", idTokenClaims["iss"])

	userInfo, ok := token.ExtraData["user_info"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "test-user", userInfo["sub"])
	assert.Equal(t, "test-user@example.com", userInfo["email"])
}
