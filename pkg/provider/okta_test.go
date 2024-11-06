package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestPKCS8Key(t *testing.T) (string, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), privateKey
}
func TestOktaClientCredentials(t *testing.T) {
	const (
		testClientID = "test-client"
	)

	tests := []struct {
		name          string
		usePrivateKey bool
		clientID      string
		clientSecret  string
		wantErr       bool
		checkRequest  func(t *testing.T, r *http.Request)
	}{
		{
			name:          "private key success",
			usePrivateKey: true,
			clientID:      testClientID,
			wantErr:       false,
			checkRequest: func(t *testing.T, r *http.Request) {
				err := r.ParseForm()
				require.NoError(t, err)

				// Verify common parameters
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/oauth2/v1/token", r.URL.Path)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))

				// Verify JWT parameters
				assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
				assert.NotEmpty(t, r.Form.Get("client_assertion"))
			},
		},
		{
			name:          "missing client secret",
			usePrivateKey: false,
			clientID:      testClientID,
			wantErr:       true,
			checkRequest:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.checkRequest != nil {
					tt.checkRequest(t, r)
				}

				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{
                    "access_token": "test-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }`))
			}))
			defer server.Close()

			opts := map[string]string{
				"domain": strings.TrimPrefix(server.URL, "http://"),
				"scheme": "http",
			}

			if tt.usePrivateKey {
				keyPEM, _ := generateTestPKCS8Key(t)
				opts["private_key"] = keyPEM
			}

			provider, err := OktaFactory(context.Background(), OktaProviderV1, opts)
			require.NoError(t, err)

			ops := provider.Private(tt.clientID, tt.clientSecret)
			token, err := ops.ClientCredentials(context.Background())

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, token)
			assert.Equal(t, "test-token", token.AccessToken)
			assert.Equal(t, "Bearer", token.TokenType)
		})
	}
}

func TestOktaUnsupportedFlows(t *testing.T) {
	provider, err := OktaFactory(context.Background(), OktaProviderV1, map[string]string{
		"domain": "test.okta.com",
	})
	require.NoError(t, err)

	ops := provider.Private("test-client", "test-secret")

	t.Run("device code auth", func(t *testing.T) {
		auth, ok, err := ops.DeviceCodeAuth(context.Background())
		assert.Nil(t, auth)
		assert.False(t, ok)
		assert.Nil(t, err)
	})

	t.Run("device code exchange", func(t *testing.T) {
		token, err := ops.DeviceCodeExchange(context.Background(), "test-code")
		assert.Nil(t, token)
		assert.EqualError(t, err, "device code flow not supported")
	})

	t.Run("auth code exchange", func(t *testing.T) {
		token, err := ops.AuthCodeExchange(context.Background(), "test-code")
		assert.Nil(t, token)
		assert.EqualError(t, err, "auth code exchange flow not supported")
	})

	t.Run("token exchange", func(t *testing.T) {
		token, err := ops.TokenExchange(context.Background(), nil)
		assert.Nil(t, token)
		assert.EqualError(t, err, "token exchange flow not supported")
	})
}
