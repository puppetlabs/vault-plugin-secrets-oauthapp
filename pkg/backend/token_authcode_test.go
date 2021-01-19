package backend

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/testutil"
	"github.com/stretchr/testify/require"
)

func TestPeriodicRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	var ti int32

	exchange := testutil.RestrictMockAuthCodeExchange(map[string]testutil.MockAuthCodeExchangeFunc{
		"first": testutil.RandomMockAuthCodeExchange,
		"second": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("second_"),
			func(_ int) (time.Duration, error) { return 30 * time.Minute, nil },
		),
		"third": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("third_"),
			func(i int) (time.Duration, error) {
				atomic.StoreInt32(&ti, int32(i))

				switch i {
				case 1:
					// Start with a short duration, which will force a refresh within
					// the library's grace period (< 10 seconds to expiry).
					return 2 * time.Second, nil
				default:
					return 10 * time.Minute, nil
				}
			},
		),
		"fourth": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("fourth_"),
			func(i int) (time.Duration, error) {
				atomic.StoreInt32(&ti, int32(i))

				// add 30 seconds for each subsequent read
				return time.Duration(i*30) * time.Second, nil
			},
		),
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

	// Write our credentials.
	for _, code := range []string{"first", "second", "third", "fourth"} {
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      credsPathPrefix + code,
			Storage:   storage,
			Data: map[string]interface{}{
				"code": code,
			},
		}

		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)
	}

	// We should have the initial step value (1) at this point.
	require.Equal(t, int32(1), ti)

	req = &logical.Request{
		Operation: logical.RollbackOperation,
		Storage:   storage,
	}

	require.NoError(t, b.PeriodicFunc(ctx, req))

	// Now we should have incremented that token (only).
	require.Equal(t, int32(2), ti)

	// Run through each of our cases and make sure nothing else got messed with.

	// "first"
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + "first",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.NotEmpty(t, resp.Data["access_token"])
	require.Empty(t, resp.Data["expire_time"])

	// make sure minimum_seconds added to first does not generate new token
	first_token := resp.Data["access_token"]
	req.Data = map[string]interface{}{
		"minimum_seconds": "60000",
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, first_token, resp.Data["access_token"])
	require.Empty(t, resp.Data["expire_time"])

	// "second"
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + "second",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "second_1", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expire_time"])

	// "third"
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + "third",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "third_2", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expire_time"])

	// test minimum_seconds more than the 30 of the first token
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      credsPathPrefix + "fourth",
		Storage:   storage,
		Data: map[string]interface{}{
			"minimum_seconds": "40",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "fourth_2", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expire_time"])

	// test minimum_seconds less than the 60 of the second token
	req.Data["minimum_seconds"] = "50"

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "fourth_2", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expire_time"])

	// test minimum_seconds more than the 60 of the second token
	req.Data["minimum_seconds"] = "70"

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Equal(t, "fourth_3", resp.Data["access_token"])
	require.NotEmpty(t, resp.Data["expire_time"])

	// verify that it is marked expired if new token is less than request
	req.Data["minimum_seconds"] = "125"

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.EqualError(t, resp.Error(), "token expired")
}
