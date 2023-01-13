package provider_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/puppetlabs/leg/timeutil/pkg/clock/k8sext"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	testclock "k8s.io/apimachinery/pkg/util/clock"
)

func TestConstantTimeoutAlgorithm(t *testing.T) {
	timeout, ok := provider.NewConstantTimeoutAlgorithm(5*time.Second).Timeout(context.Background(), nil)
	require.Equal(t, true, ok)
	require.Equal(t, 5*time.Second, timeout)
}

func TestTimeToExpiryPiecewiseTimeoutAlgorithm(t *testing.T) {
	clk := testclock.NewFakeClock(time.Now())
	ctx := clockctx.WithClock(context.Background(), k8sext.NewClock(clk))

	tests := []struct {
		Name     string
		Expiry   time.Time
		Mappings []provider.TimeToExpiryPiecewiseTimeoutMapping
		Expected time.Duration
	}{
		{
			Name: "Empty",
		},
		{
			Name: "No expiry",
			Mappings: []provider.TimeToExpiryPiecewiseTimeoutMapping{
				{
					Test:      func(d time.Duration, ok bool) bool { return ok },
					Algorithm: provider.NewConstantTimeoutAlgorithm(10 * time.Second),
				},
				{
					Algorithm: provider.NewConstantTimeoutAlgorithm(5 * time.Second),
				},
			},
			Expected: 5 * time.Second,
		},
		{
			Name:   "Expiry cases",
			Expiry: clk.Now().Add(15 * time.Second),
			Mappings: []provider.TimeToExpiryPiecewiseTimeoutMapping{
				{
					Test:      func(d time.Duration, ok bool) bool { return ok && d >= 20*time.Second },
					Algorithm: provider.NewConstantTimeoutAlgorithm(15 * time.Second),
				},
				{
					Test:      func(d time.Duration, ok bool) bool { return ok && d >= 10*time.Second },
					Algorithm: provider.NewConstantTimeoutAlgorithm(10 * time.Second),
				},
				{
					Algorithm: provider.NewConstantTimeoutAlgorithm(5 * time.Second),
				},
			},
			Expected: 10 * time.Second,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			tok := &provider.Token{
				Token: &oauth2.Token{
					AccessToken: "token",
					Expiry:      test.Expiry,
				},
			}
			alg := provider.NewTimeToExpiryPiecewiseTimeoutAlgorithm(test.Mappings)

			timeout, ok := alg.Timeout(ctx, tok)
			require.Equal(t, test.Expected > 0, ok)
			require.Equal(t, test.Expected, timeout)
		})
	}
}

func TestLogarithmicTimeoutAlgorithm(t *testing.T) {
	clk := testclock.NewFakeClock(time.Now())
	ctx := clockctx.WithClock(context.Background(), k8sext.NewClock(clk))

	tests := []struct {
		Name               string
		Expiry             time.Time
		ExpiryLeewayFactor float64
		Timeout            time.Duration
		ExpiryDelta        time.Duration
		Expected           func(t *testing.T, actual time.Duration)
		ExpectedBounded    func(t *testing.T, actual time.Duration)
	}{
		{
			Name:               "At expiry delta",
			Expiry:             clk.Now().Add(10 * time.Second),
			ExpiryLeewayFactor: 1.5,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Equal(t, 15*time.Second, actual)
			},
		},
		{
			Name:               "At 0",
			Expiry:             clk.Now(),
			ExpiryLeewayFactor: 1.5,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Equal(t, 22*time.Second+500*time.Millisecond, actual)
			},
		},
		{
			Name:               "Between expiry delta and 0",
			Expiry:             clk.Now().Add(5 * time.Second),
			ExpiryLeewayFactor: 1.5,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Greater(t, int64(actual), int64(15*time.Second))
				require.Less(t, int64(actual), int64(22*time.Second+500*time.Millisecond))
			},
		},
		{
			Name:               "Already expired",
			Expiry:             clk.Now().Add(-5 * time.Second),
			ExpiryLeewayFactor: 1.5,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Equal(t, 22*time.Second+500*time.Millisecond, actual)
			},
		},
		{
			Name:               "Expiry after expiry delta",
			Expiry:             clk.Now().Add(15 * time.Second),
			ExpiryLeewayFactor: 1.5,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Greater(t, int64(actual), int64(0))
				require.Less(t, int64(actual), int64(15*time.Second))
			},
			ExpectedBounded: func(t *testing.T, actual time.Duration) {
				require.Equal(t, 15*time.Second, actual)
			},
		},
		{
			Name:               "Expiry in the distant future",
			Expiry:             clk.Now().Add(15 * time.Hour),
			ExpiryLeewayFactor: 1.5,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Equal(t, time.Duration(0), actual)
			},
			ExpectedBounded: func(t *testing.T, actual time.Duration) {
				require.Equal(t, 15*time.Second, actual)
			},
		},
		{
			Name:               "Token does not expire",
			ExpiryLeewayFactor: 1.5,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Equal(t, 15*time.Second, actual)
			},
		},
		{
			Name:               "Leeway cannot produce logarithmic function",
			Expiry:             clk.Now().Add(10 * time.Second),
			ExpiryLeewayFactor: 1.0,
			Timeout:            15 * time.Second,
			ExpiryDelta:        10 * time.Second,
			Expected: func(t *testing.T, actual time.Duration) {
				require.Equal(t, 15*time.Second, actual)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			tok := &provider.Token{
				Token: &oauth2.Token{
					AccessToken: "token",
					Expiry:      test.Expiry,
				},
			}

			t.Run("Unbounded", func(t *testing.T) {
				alg := provider.NewLogarithmicTimeoutAlgorithm(test.ExpiryLeewayFactor, test.Timeout, test.ExpiryDelta)

				timeout, ok := alg.Timeout(ctx, tok)
				require.Equal(t, true, ok)

				test.Expected(t, timeout)
			})

			t.Run("Bounded", func(t *testing.T) {
				alg := provider.NewBoundedLogarithmicTimeoutAlgorithm(test.ExpiryLeewayFactor, test.Timeout, test.ExpiryDelta)

				timeout, ok := alg.Timeout(ctx, tok)
				require.Equal(t, true, ok)

				expected := test.ExpectedBounded
				if expected == nil {
					expected = test.Expected
				}
				expected(t, timeout)
			})
		})
	}
}

func TestTimeoutProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clk := testclock.NewFakeClock(time.Now())
	ctx = clockctx.WithClock(ctx, k8sext.NewClock(clk))

	stepper := make(chan time.Duration, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			select {
			case d := <-stepper:
				clk.Step(d)
			default:
			}

			b, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			data, err := url.ParseQuery(string(b))
			require.NoError(t, err)

			switch data.Get("grant_type") {
			case "authorization_code":
				switch data.Get("code") {
				case "issue":
					_, _ = w.Write([]byte(`access_token=abcd&refresh_token=efgh&token_type=bearer&expires_in=60`))
				default:
					<-ctx.Done()
				}
			default:
				<-ctx.Done()
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
		Transport: &testutil.MockRoundTripper{
			Handler: h,
		},
	})

	factory := provider.BasicFactory(provider.Endpoint{
		Endpoint: oauth2.Endpoint{
			TokenURL:  "http://localhost/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	})

	p, err := factory(ctx, 1, map[string]string{})
	require.NoError(t, err)

	alg := provider.NewBoundedLogarithmicTimeoutAlgorithm(1.5, 10*time.Second, time.Minute)
	p = provider.NewTimeoutProvider(p, alg)

	ops := p.Private("foo", "bar")

	// Get a token. This should return immediately.
	tok, err := ops.AuthCodeExchange(ctx, "issue")
	require.NoError(t, err)

	// If we try to refresh this token now, we're at the beginning of the expiry
	// range, so we should only have to step by 10 seconds to cause a timeout.
	stepper <- 10 * time.Second
	_, err = ops.RefreshToken(ctx, tok)
	require.Equal(t, context.DeadlineExceeded, err)

	// Step the remaining 50 seconds to get exactly to the end of the expiry
	// delta, with a maximum leeway.
	clk.Step(tok.Expiry.Sub(clk.Now()))

	// We now have to wait 15 seconds with a leeway factor of 1.5.
	stepper <- 15 * time.Second
	_, err = ops.RefreshToken(ctx, tok)
	require.Equal(t, context.DeadlineExceeded, err)

	// Issuing a new token will retain the default 10 second timeout.
	stepper <- 10 * time.Second
	_, err = ops.AuthCodeExchange(ctx, "wait")
	require.Equal(t, context.DeadlineExceeded, err)
}
