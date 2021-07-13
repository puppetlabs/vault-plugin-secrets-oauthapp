package backend_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"github.com/puppetlabs/leg/timeutil/pkg/clock/k8sext"
	"github.com/puppetlabs/leg/timeutil/pkg/retry"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/backend"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/testutil"
	"github.com/stretchr/testify/require"
	testclock "k8s.io/apimachinery/pkg/util/clock"
)

func TestPeriodicReap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	clk := testclock.NewFakeClock(time.Now())
	exchange := testutil.AmendTokenMockAuthCodeExchange(testutil.RandomMockAuthCodeExchange, func(tok *provider.Token) error {
		tok.Expiry = clk.Now().Add(time.Minute)
		return nil
	})

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, exchange)))

	storage := &logical.InmemStorage{}

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
			"client_id":                         client.ID,
			"client_secret":                     client.Secret,
			"provider":                          "mock",
			"tune_reap_non_refreshable_seconds": "5m",
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write our credentials.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + "test",
		Storage:   storage,
		Data: map[string]interface{}{
			"code": "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Actual expiration of the token.
	wait := time.Minute
	// Non-refreshable token reap delay.
	wait += 5 * time.Minute
	// One more time around the reaper for good measure.
	wait += time.Duration(persistence.DefaultConfigTuningEntry.ReapCheckIntervalSeconds) * time.Second

	select {
	case <-clk.After(wait):
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for reaper to run")
	}

	// Now our token should be deleted.
	require.NoError(t, retry.Wait(ctx, func(ctx context.Context) (bool, error) {
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      backend.CredsPathPrefix + "test",
			Storage:   storage,
		}

		// Now the token should be deleted.
		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)

		if resp != nil {
			return retry.Repeat(fmt.Errorf("token still exists"))
		}

		return retry.Done(nil)
	}))
}
