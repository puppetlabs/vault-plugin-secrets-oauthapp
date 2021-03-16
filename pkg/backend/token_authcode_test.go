package backend_test

import (
	"context"
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

	// We may have at most 2 writes with no reads (third and fourth token,
	// below).
	refreshed := make(chan int, 2)

	exchange := testutil.RestrictMockAuthCodeExchange(map[string]testutil.MockAuthCodeExchangeFunc{
		"first": testutil.RandomMockAuthCodeExchange,
		"second": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("second_"),
			func(_ int) (time.Duration, error) { return 30 * time.Minute, nil },
		),
		"third": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("third_"),
			func(i int) (time.Duration, error) {
				select {
				case refreshed <- i:
				default:
				}

				switch i {
				case 1, 2:
					// Start with a short duration. This will be refreshed
					// automatically when the scheduler boots and then again by
					// incrementing the clock.
					return 5 * time.Second, nil
				default:
					return 10 * time.Minute, nil
				}
			},
		),
		"fourth": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("fourth_"),
			func(i int) (time.Duration, error) {
				select {
				case refreshed <- i:
				default:
				}

				// add 30 seconds for each subsequent read
				return (60 + time.Duration(i)*30) * time.Second, nil
			},
		),
	})

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, exchange)))

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
	for _, code := range []string{"first", "second", "third", "fourth"} {
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

	// We should have the initial step value (1) at this point for tokens 3 and
	// 4.
	for i := 0; i < 2; i++ {
		select {
		case ti := <-refreshed:
			// Now we should have incremented that token (only).
			require.Equal(t, 1, ti)
		case <-ctx.Done():
			require.Fail(t, "context expired waiting for token issuance")
		}
	}

	// Move the clock forward once. This should "bump" the recovery descriptors
	// of the segment and make them spin up our descriptors.
	//
	// TODO: Is it safe to depend on this behavior?
	clk.Step(1)

	select {
	case ti := <-refreshed:
		// Now we should have incremented that token (only).
		require.Equal(t, 2, ti)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for token refresh")
	}

	// Now we increment the clock by a minute and we should once again get the
	// refresh we want.
	clk.Step(time.Minute)

	select {
	case ti := <-refreshed:
		// Now we should have incremented that token (only).
		require.Equal(t, 3, ti)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for token refresh")
	}

	// Run through each of our cases and make sure nothing else got messed with.
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
		{
			Name:                "second",
			Token:               "second",
			ExpectedAccessToken: func() string { return "second_1" },
			ExpectedExpireTime:  true,
		},
		{
			Name:                "third",
			Token:               "third",
			ExpectedAccessToken: func() string { return "third_3" },
			ExpectedExpireTime:  true,
		},
		// The fourth token will now expire at +1m30s, of which we've already
		// elapsed +1m. 40 more seconds will get us a refresh.
		{
			Name:                "fourth initial",
			Token:               "fourth",
			Data:                map[string]interface{}{"minimum_seconds": "40"},
			ExpectedAccessToken: func() string { return "fourth_2" },
			ExpectedExpireTime:  true,
		},
		{
			Name:                "test minimum_seconds less than the 60 of the fourth token",
			Token:               "fourth",
			Data:                map[string]interface{}{"minimum_seconds": "50"},
			ExpectedAccessToken: func() string { return "fourth_2" },
			ExpectedExpireTime:  true,
		},
		{
			Name:                "test minimum_seconds more than the 60 of the fourth token",
			Token:               "fourth",
			Data:                map[string]interface{}{"minimum_seconds": "70"},
			ExpectedAccessToken: func() string { return "fourth_3" },
			ExpectedExpireTime:  true,
		},
		{
			Name:          "verify that fourth is marked expired if new token is less than request",
			Token:         "fourth",
			Data:          map[string]interface{}{"minimum_seconds": "125"},
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
