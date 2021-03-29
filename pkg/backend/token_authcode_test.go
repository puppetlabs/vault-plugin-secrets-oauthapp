package backend_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clock/k8sext"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/testutil"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/clock"
)

func TestPeriodicRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	// We may have at most 3 writes with no reads (second, third token issuance
	// and third token refresh).
	refreshed := make(chan int, 3)

	exchanges := map[string]testutil.MockAuthCodeExchangeFunc{
		"first": testutil.RandomMockAuthCodeExchange,
		"second": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("second_"),
			func(i int) (time.Duration, error) {
				select {
				case refreshed <- i:
				default:
				}

				return 30 * time.Minute, nil
			},
		),
		"third": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("third_"),
			func(i int) (time.Duration, error) {
				select {
				case refreshed <- i:
				default:
				}

				switch i {
				case 1:
					// We start with an expiry that falls within our default
					// expiration window (70 seconds) but will also be valid if
					// we tick the clock forward a minute. That way we don't
					// have a race condition on scheduler startup.
					return 65 * time.Second, nil
				default:
					return 10 * time.Minute, nil
				}
			},
		),
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, testutil.RestrictMockAuthCodeExchange(exchanges))))

	storage := &logical.InmemStorage{}

	clk := clock.NewFakeClock(time.Now())

	b := backend.New(backend.Options{
		ProviderRegistry: pr,
		Clock:            k8sext.NewClock(clk),
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
	for code := range exchanges {
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      backend.CredsPathPrefix + code,
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

	// We should have the initial step value (1) at this point for the tokens.
	for i := 0; i < 2; i++ {
		select {
		case ti := <-refreshed:
			// Now we should have incremented that token (only).
			require.Equal(t, 1, ti)
		case <-ctx.Done():
			require.Fail(t, "context expired waiting for token issuance")
		}
	}

	// Now we increment the clock into the range where the third token will be
	// refreshed regardless of where the scheduler is at in its startup routine.
	for !clk.HasWaiters() {
		runtime.Gosched()
	}
	clk.Step(time.Minute)

	select {
	case ti := <-refreshed:
		// Now we should have incremented that token (only).
		require.Equal(t, 2, ti)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for token refresh")
	}
}

func TestMinimumSeconds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	exchanges := map[string]testutil.MockAuthCodeExchangeFunc{
		"first": testutil.RandomMockAuthCodeExchange,
		"second": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("second_"),
			func(i int) (time.Duration, error) {
				// add 30 seconds for each subsequent read
				return (70 + time.Duration(i)*30) * time.Second, nil
			},
		),
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, testutil.RestrictMockAuthCodeExchange(exchanges))))

	storage := &logical.InmemStorage{}

	b := backend.New(backend.Options{
		ProviderRegistry: pr,
	})
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{}))
	defer b.Clean(ctx)

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

	// Write our credentials.
	for code := range exchanges {
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      backend.CredsPathPrefix + code,
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

	tokens := make(map[string]string)
	tests := []struct {
		Name                string
		Token               string
		Data                map[string]interface{}
		ExpectedAccessToken func() string
		ExpectedExpireTime  bool
		ExpectedError       string
	}{
		{
			Name:  "first",
			Token: "first",
		},
		{
			Name:                "make sure minimum_seconds added to first does not generate new token",
			Token:               "first",
			ExpectedAccessToken: func() string { return tokens["first"] },
		},
		// The initial token will be issued at +100s (70 seconds + 30 seconds),
		// so we force a refresh with a requirement of +110s.
		{
			Name:                "second initial",
			Token:               "second",
			Data:                map[string]interface{}{"minimum_seconds": "110"},
			ExpectedAccessToken: func() string { return "second_2" },
			ExpectedExpireTime:  true,
		},
		// The token should now be issued for +130s, so asking for anything
		// under that should let us keep the token as-is.
		{
			Name:                "test minimum_seconds less than the expiry of the second token",
			Token:               "second",
			Data:                map[string]interface{}{"minimum_seconds": "120"},
			ExpectedAccessToken: func() string { return "second_2" },
			ExpectedExpireTime:  true,
		},
		// If we ask for +140s (> +130s), we should get another refresh.
		{
			Name:                "test minimum_seconds more than the expiry of the second token",
			Token:               "second",
			Data:                map[string]interface{}{"minimum_seconds": "140"},
			ExpectedAccessToken: func() string { return "second_3" },
			ExpectedExpireTime:  true,
		},
		// Finally, if we ask for something outside the range of what we can
		// reasonably issue, we'll just get an error.
		{
			Name:          "verify that second is marked expired if new token is less than request",
			Token:         "second",
			Data:          map[string]interface{}{"minimum_seconds": "200"},
			ExpectedError: "token expired",
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      backend.CredsPathPrefix + test.Token,
				Storage:   storage,
				Data:      test.Data,
			}

			resp, err := b.HandleRequest(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			if test.ExpectedError != "" {
				require.True(t, resp.IsError())
				require.EqualError(t, resp.Error(), test.ExpectedError)
			} else {
				require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
				require.Equal(t, test.ExpectedExpireTime, resp.Data["expire_time"] != nil)

				if test.ExpectedAccessToken != nil {
					require.Equal(t, test.ExpectedAccessToken(), resp.Data["access_token"])
				} else {
					require.NotEmpty(t, resp.Data["access_token"])
				}

				tokens[test.Token] = resp.Data["access_token"].(string)
			}
		})
	}
}
