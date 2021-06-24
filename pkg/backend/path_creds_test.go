package backend_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"github.com/puppetlabs/leg/timeutil/pkg/clock/k8sext"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/devicecode"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	testclock "k8s.io/apimachinery/pkg/util/clock"
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

	// Write a valid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + `test`,
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
		Path:      backend.CredsPathPrefix + `test`,
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

	// Write an invalid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"code": "invalid",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "exchange failed: server rejected request: unauthorized_client")
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

	// Prepend the tenant provider option to the resulting token.
	handler := func(code string, opts *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		t, err := exchange(code, opts)
		if err != nil {
			return nil, err
		}

		t.AccessToken = fmt.Sprintf("%s_%s", opts.ProviderOptions["tenant"], t.AccessToken)
		return t, nil
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, handler)))

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

	// Write a valid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"code": "test",
			"provider_options": map[string]interface{}{
				"tenant": "test",
			},
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
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "test_token_2", resp.Data["access_token"])
	require.Equal(t, "Bearer", resp.Data["type"])
	require.NotEmpty(t, resp.Data["expire_time"])
	require.Equal(t, map[string]string{"tenant": "test"}, resp.Data["provider_options"])
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

	// Write a valid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + `test`,
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
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "token expired")
}

func TestDeviceCodeAuthAndExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{ID: "abc"}

	auth := testutil.StaticMockDeviceCodeAuth(&devicecode.Auth{
		DeviceCode:              "xyz123",
		UserCode:                "ABCD-1234",
		VerificationURI:         "http://localhost/verify",
		VerificationURIComplete: "http://localhost/verify?user_code=ABCD-1234",
		ExpiresIn:               300,
		Interval:                5,
	})

	// This contains the state of the issuer: either 0 (pending), 1 (request to
	// issue), or 2 (issued).
	var issue int32
	exchange := func(deviceCode string, opts *provider.DeviceCodeExchangeOptions) (*provider.Token, error) {
		require.Equal(t, "xyz123", deviceCode)

		switch {
		case atomic.CompareAndSwapInt32(&issue, 1, 2) || atomic.LoadInt32(&issue) > 1:
			atomic.AddInt32(&issue, 1)
			return &provider.Token{Token: &oauth2.Token{AccessToken: "hello"}}, nil
		default:
			return testutil.AuthorizationPendingErrorMockDeviceCodeExchange(deviceCode, opts)
		}
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(
		testutil.MockWithDeviceCodeAuth(client, auth),
		testutil.MockWithDeviceCodeExchange(client, exchange),
	))

	storage := &logical.InmemStorage{}

	clk := testclock.NewFakeClock(time.Now())

	b := backend.New(backend.Options{
		ProviderRegistry: pr,
		Clock: clock.NewTimerCallbackClock(
			k8sext.NewClock(clk),
			func(d time.Duration) {
				// Stepping the clock every time a timer is created or reset
				// guarantees that the normally-delayed timer will immediately
				// retry over and over.
				clk.Step(d)
			},
		),
	})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))
	require.NoError(t, b.Initialize(ctx, &logical.InitializationRequest{Storage: storage}))
	defer b.Clean(ctx)

	// Write configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id": client.ID,
			"provider":  "mock",
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write a valid credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"grant_type": devicecode.GrantType,
			"scopes":     []interface{}{"first", "second"},
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "ABCD-1234", resp.Data["user_code"])
	require.Equal(t, "http://localhost/verify", resp.Data["verification_uri"])
	require.Equal(t, "http://localhost/verify?user_code=ABCD-1234", resp.Data["verification_uri_complete"])
	require.NotEmpty(t, resp.Data["expire_time"])

	// Token should now be pending.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "token pending issuance")

	require.Equal(t, int32(1), atomic.AddInt32(&issue, 1))
	for atomic.LoadInt32(&issue) == 1 {
		select {
		case <-ctx.Done():
			require.Fail(t, "context expired waiting for token issuance")
		default:
		}
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "hello", resp.Data["access_token"])
	require.Equal(t, "Bearer", resp.Data["type"])
	require.Empty(t, resp.Data["expire_time"])
}
