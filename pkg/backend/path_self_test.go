package backend_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clock/k8sext"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	testclock "k8s.io/apimachinery/pkg/util/clock"
)

func TestClientCredentials(t *testing.T) {
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

	// Write credential configuration.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.SelfPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"server": "mock",
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

	// Write credential configuration.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.SelfPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"server": "mock",
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

func TestClientCredentialsMaximumExpiry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	tests := []struct {
		Name              string
		ExchangeFunc      testutil.MockClientCredentialsFunc
		CredMaximumExpiry time.Duration
		Step              time.Duration
		ExpectedError     string
		ExpectedToken     string
		ExpectedExpiry    time.Duration
	}{
		{
			Name:              "no server expiry",
			ExchangeFunc:      testutil.IncrementMockClientCredentials("token_"),
			CredMaximumExpiry: 120 * time.Second,
			ExpectedToken:     "token_1",
			ExpectedExpiry:    120 * time.Second,
		},
		{
			Name:              "no server expiry but expiry is forced",
			ExchangeFunc:      testutil.IncrementMockClientCredentials("token_"),
			CredMaximumExpiry: 2 * time.Second,
			ExpectedError:     "token expired",
		},
		{
			Name:              "server expiry after maximum",
			ExchangeFunc:      testutil.ExpiringMockClientCredentials(testutil.IncrementMockClientCredentials("token_"), 2*time.Hour),
			CredMaximumExpiry: 120 * time.Second,
			ExpectedToken:     "token_1",
			ExpectedExpiry:    120 * time.Second,
		},
		{
			Name:              "maximum expiry forces early refresh",
			ExchangeFunc:      testutil.ExpiringMockClientCredentials(testutil.IncrementMockClientCredentials("token_"), 2*time.Hour),
			CredMaximumExpiry: 120 * time.Second,
			Step:              115 * time.Second,
			ExpectedToken:     "token_2",
			ExpectedExpiry:    120 * time.Second,
		},
		{
			Name:              "server expiry before maximum",
			ExchangeFunc:      testutil.ExpiringMockClientCredentials(testutil.IncrementMockClientCredentials("token_"), 2*time.Hour),
			CredMaximumExpiry: 24 * time.Hour,
			ExpectedToken:     "token_1",
			ExpectedExpiry:    2 * time.Hour,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			clk := testclock.NewFakeClock(time.Now())

			pr := provider.NewRegistry()
			pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithClientCredentials(client, test.ExchangeFunc)))

			storage := &logical.InmemStorage{}

			b, err := backend.New(backend.Options{
				ProviderRegistry: pr,
				Clock:            k8sext.NewClock(clk),
			})
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
				Path:      backend.SelfPathPrefix + `test`,
				Storage:   storage,
				Data: map[string]interface{}{
					"server":                 "mock",
					"code":                   "test",
					"maximum_expiry_seconds": test.CredMaximumExpiry.Seconds(),
				},
			}

			resp, err = b.HandleRequest(ctx, req)
			require.NoError(t, err)
			require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
			require.Nil(t, resp)

			// Move time forward if necessary.
			clk.Step(test.Step)

			// Read the resulting token.
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      backend.SelfPathPrefix + `test`,
				Storage:   storage,
			}

			resp, err = b.HandleRequest(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			if test.ExpectedError != "" {
				require.True(t, resp.IsError())
				require.EqualError(t, resp.Error(), test.ExpectedError)
			} else {
				require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
				require.Equal(t, test.ExpectedToken, resp.Data["access_token"])
				require.Equal(t, "Bearer", resp.Data["type"])
				require.IsType(t, time.Time{}, resp.Data["expire_time"])
				require.LessOrEqual(t, clk.Now().Sub(resp.Data["expire_time"].(time.Time)), test.ExpectedExpiry)
			}
		})
	}
}
