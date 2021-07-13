package provider

import (
	"context"
	"math"
	"time"

	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/devicecode"
)

type TimeoutAlgorithm interface {
	Timeout(ctx context.Context, tok *Token) (time.Duration, bool)
}

func contextWithTimeout(ctx context.Context, alg TimeoutAlgorithm, tok *Token) (context.Context, context.CancelFunc) {
	timeout, ok := alg.Timeout(ctx, tok)
	if !ok {
		return context.WithCancel(ctx)
	}

	return clockctx.WithTimeout(ctx, timeout)
}

type ConstantTimeoutAlgorithm struct {
	timeout time.Duration
}

var _ TimeoutAlgorithm = &ConstantTimeoutAlgorithm{}

func (cta *ConstantTimeoutAlgorithm) Timeout(ctx context.Context, tok *Token) (time.Duration, bool) {
	return cta.timeout, true
}

func NewConstantTimeoutAlgorithm(timeout time.Duration) *ConstantTimeoutAlgorithm {
	return &ConstantTimeoutAlgorithm{
		timeout: timeout,
	}
}

type TimeToExpiryPiecewiseTimeoutMapping struct {
	Test      func(d time.Duration, ok bool) bool
	Algorithm TimeoutAlgorithm
}

type TimeToExpiryPiecewiseTimeoutAlgorithm struct {
	mappings []TimeToExpiryPiecewiseTimeoutMapping
}

var _ TimeoutAlgorithm = &TimeToExpiryPiecewiseTimeoutAlgorithm{}

func (ttepta *TimeToExpiryPiecewiseTimeoutAlgorithm) Timeout(ctx context.Context, tok *Token) (time.Duration, bool) {
	remaining, ok := timeToExpiry(ctx, tok)

	for _, mapping := range ttepta.mappings {
		if fn := mapping.Test; fn == nil || fn(remaining, ok) {
			return mapping.Algorithm.Timeout(ctx, tok)
		}
	}

	return 0, false
}

func NewTimeToExpiryPiecewiseTimeoutAlgorithm(mappings []TimeToExpiryPiecewiseTimeoutMapping) *TimeToExpiryPiecewiseTimeoutAlgorithm {
	return &TimeToExpiryPiecewiseTimeoutAlgorithm{
		mappings: mappings,
	}
}

type LogarithmicTimeoutAlgorithm struct {
	expiryLeewayFactor float64
	timeout            time.Duration
	expiryDelta        time.Duration
}

var _ TimeoutAlgorithm = &LogarithmicTimeoutAlgorithm{}

func (lta *LogarithmicTimeoutAlgorithm) Timeout(ctx context.Context, tok *Token) (time.Duration, bool) {
	remaining, ok := timeToExpiry(ctx, tok)
	if !ok {
		return lta.timeout, true
	}

	// This function will scale by 1 when remaining is exactly at the
	// expiryDelta and by the leeway factor when remaining is 0.
	//
	// Note these values are constant vis-a-vis the fields of the struct, so
	// could be calculated early, but it feels clearer here.
	start := lta.expiryDelta.Seconds()
	target := math.Pow(10, 1.0-lta.expiryLeewayFactor)
	factor := (start * target) / (1.0 - target)

	// Calcluate the appropriate scale value.
	scale := 1 - math.Log10((factor+remaining.Seconds())/(start+factor))
	if math.IsNaN(scale) {
		// Past asymptote or leeway isn't valid (e.g., is exactly 1.0), set
		// scale to leeway factor.
		scale = lta.expiryLeewayFactor
	} else if scale < 0 {
		// Below x-axis, set scale to 0 to prevent returning negative number
		// (although this will immediate cause a timeout anyway).
		scale = 0
	}

	return time.Duration(float64(lta.timeout) * scale), true
}

func NewLogarithmicTimeoutAlgorithm(expiryLeewayFactor float64, timeout, expiryDelta time.Duration) *LogarithmicTimeoutAlgorithm {
	return &LogarithmicTimeoutAlgorithm{
		expiryLeewayFactor: expiryLeewayFactor,
		timeout:            timeout,
		expiryDelta:        expiryDelta,
	}
}

func NewBoundedLogarithmicTimeoutAlgorithm(expiryLeewayFactor float64, timeout, expiryDelta time.Duration) TimeoutAlgorithm {
	return NewTimeToExpiryPiecewiseTimeoutAlgorithm([]TimeToExpiryPiecewiseTimeoutMapping{
		{
			Test:      func(d time.Duration, ok bool) bool { return !ok || d >= expiryDelta },
			Algorithm: NewConstantTimeoutAlgorithm(timeout),
		},
		{
			Algorithm: NewLogarithmicTimeoutAlgorithm(expiryLeewayFactor, timeout, expiryDelta),
		},
	})
}

func timeToExpiry(ctx context.Context, tok *Token) (time.Duration, bool) {
	now := clockctx.Clock(ctx).Now()

	var expiry time.Time
	if tok != nil && tok.Token != nil && tok.AccessToken != "" {
		expiry = tok.Expiry
	}

	if expiry.IsZero() {
		return 0, false
	}

	return expiry.Sub(now), true
}

type publicTimeoutOperations struct {
	delegate PublicOperations
	alg      TimeoutAlgorithm
}

func (pto *publicTimeoutOperations) AuthCodeURL(state string, opts ...AuthCodeURLOption) (string, bool) {
	return pto.delegate.AuthCodeURL(state, opts...)
}

func (pto *publicTimeoutOperations) DeviceCodeAuth(ctx context.Context, opts ...DeviceCodeAuthOption) (*devicecode.Auth, bool, error) {
	ctx, cancel := contextWithTimeout(ctx, pto.alg, nil)
	defer cancel()

	return pto.delegate.DeviceCodeAuth(ctx, opts...)
}

func (pto *publicTimeoutOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...DeviceCodeExchangeOption) (*Token, error) {
	ctx, cancel := contextWithTimeout(ctx, pto.alg, nil)
	defer cancel()

	return pto.delegate.DeviceCodeExchange(ctx, deviceCode, opts...)
}

func (pto *publicTimeoutOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	ctx, cancel := contextWithTimeout(ctx, pto.alg, t)
	defer cancel()

	return pto.delegate.RefreshToken(ctx, t, opts...)
}

type privateTimeoutOperations struct {
	*publicTimeoutOperations
	delegate PrivateOperations
}

func (pto *privateTimeoutOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	ctx, cancel := contextWithTimeout(ctx, pto.alg, nil)
	defer cancel()

	return pto.delegate.AuthCodeExchange(ctx, code, opts...)
}

func (pto *privateTimeoutOperations) ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error) {
	ctx, cancel := contextWithTimeout(ctx, pto.alg, nil)
	defer cancel()

	return pto.delegate.ClientCredentials(ctx, opts...)
}

type TimeoutProvider struct {
	delegate Provider
	alg      TimeoutAlgorithm
}

var _ Provider = &TimeoutProvider{}

func (tp *TimeoutProvider) Version() int {
	return tp.delegate.Version()
}

func (tp *TimeoutProvider) Public(clientID string) PublicOperations {
	return &publicTimeoutOperations{
		delegate: tp.delegate.Public(clientID),
		alg:      tp.alg,
	}
}

func (tp *TimeoutProvider) Private(clientID, clientSecret string) PrivateOperations {
	priv := tp.delegate.Private(clientID, clientSecret)
	return &privateTimeoutOperations{
		publicTimeoutOperations: &publicTimeoutOperations{
			delegate: priv,
			alg:      tp.alg,
		},
		delegate: priv,
	}
}

func NewTimeoutProvider(delegate Provider, alg TimeoutAlgorithm) *TimeoutProvider {
	return &TimeoutProvider{
		delegate: delegate,
		alg:      alg,
	}
}
