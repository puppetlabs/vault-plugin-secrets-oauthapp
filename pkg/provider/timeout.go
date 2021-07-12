package provider

import (
	"context"
	"math"
	"time"

	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/devicecode"
)

type TimeoutAlgorithm interface {
	ContextWithTimeout(ctx context.Context, tok *Token) (context.Context, context.CancelFunc)
}

type noTimeoutAlgorithm struct{}

func (*noTimeoutAlgorithm) ContextWithTimeout(ctx context.Context, tok *Token) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}

var NoTimeoutAlgorithm TimeoutAlgorithm = &noTimeoutAlgorithm{}

type ConstantTimeoutAlgorithm struct {
	timeout time.Duration
}

func (cta *ConstantTimeoutAlgorithm) ContextWithTimeout(ctx context.Context, tok *Token) (context.Context, context.CancelFunc) {
	return clockctx.WithTimeout(ctx, cta.timeout)
}

func NewConstantTimeoutAlgorithm(timeout time.Duration) *ConstantTimeoutAlgorithm {
	return &ConstantTimeoutAlgorithm{
		timeout: timeout,
	}
}

type TimeToExpiryPiecewiseTimeoutMapping struct {
	Test      func(d time.Duration) bool
	Algorithm TimeoutAlgorithm
}

type TimeToExpiryPiecewiseTimeoutAlgorithm struct {
	mappings []TimeToExpiryPiecewiseTimeoutMapping
}

func (ttepta *TimeToExpiryPiecewiseTimeoutAlgorithm) ContextWithTimeout(ctx context.Context, tok *Token) (context.Context, context.CancelFunc) {
	remaining, ok := timeToExpiry(ctx, tok)
	if !ok {
		return NoTimeoutAlgorithm.ContextWithTimeout(ctx, tok)
	}

	for _, mapping := range ttepta.mappings {
		if fn := mapping.Test; fn == nil || fn(remaining) {
			return mapping.Algorithm.ContextWithTimeout(ctx, tok)
		}
	}

	return NoTimeoutAlgorithm.ContextWithTimeout(ctx, tok)
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

func (lta *LogarithmicTimeoutAlgorithm) ContextWithTimeout(ctx context.Context, tok *Token) (context.Context, context.CancelFunc) {
	remaining, ok := timeToExpiry(ctx, tok)
	if !ok {
		return clockctx.WithTimeout(ctx, lta.timeout)
	}

	// This function will scale by 1 when remaining is exactly at the
	// expiryDelta and by the leeway factor when remaining is 0.
	//
	// Note these values are constant vis-a-vis the fields of the struct, so
	// could be calculated early, but it feels clearer here.
	start := lta.expiryDelta.Seconds()
	target := math.Pow(10, 1-lta.expiryLeewayFactor)
	factor := (start * target) / (1 - target)

	// Calcluate the appropriate scale value.
	scale := 1 - math.Log10((factor-remaining.Seconds())/(start+factor))
	if math.IsNaN(scale) || math.IsInf(scale, 0) || scale < 0 {
		return NoTimeoutAlgorithm.ContextWithTimeout(ctx, tok)
	}

	timeout := time.Duration(float64(lta.timeout) * scale)
	return clockctx.WithTimeout(ctx, timeout)
}

func NewLogarithmicTimeoutAlgorithm(expiryLeewayFactor float64, timeout, expiryDelta time.Duration) *LogarithmicTimeoutAlgorithm {
	return &LogarithmicTimeoutAlgorithm{
		expiryLeewayFactor: expiryLeewayFactor,
		timeout:            timeout,
		expiryDelta:        expiryDelta,
	}
}

type IfExpiresTimeoutAlgorithm struct {
	ifExpires TimeoutAlgorithm
	otherwise TimeoutAlgorithm
}

func (ieta *IfExpiresTimeoutAlgorithm) ContextWithTimeout(ctx context.Context, tok *Token) (context.Context, context.CancelFunc) {
	if _, ok := timeToExpiry(ctx, tok); ok {
		return ieta.ifExpires.ContextWithTimeout(ctx, tok)
	}

	return ieta.otherwise.ContextWithTimeout(ctx, tok)
}

func NewIfExpiresTimeoutAlgorithm(ifExpires, otherwise TimeoutAlgorithm) *IfExpiresTimeoutAlgorithm {
	return &IfExpiresTimeoutAlgorithm{
		ifExpires: ifExpires,
		otherwise: otherwise,
	}
}

func NewBoundedLogarithmicTimeoutAlgorithm(expiryLeewayFactor float64, timeout, expiryDelta time.Duration) TimeoutAlgorithm {
	min := NewConstantTimeoutAlgorithm(timeout)
	max := NewConstantTimeoutAlgorithm(time.Duration(float64(timeout) * expiryLeewayFactor))

	alg := NewTimeToExpiryPiecewiseTimeoutAlgorithm([]TimeToExpiryPiecewiseTimeoutMapping{
		{
			Test:      func(d time.Duration) bool { return d >= expiryDelta },
			Algorithm: min,
		},
		{
			Test:      func(d time.Duration) bool { return d <= 0 },
			Algorithm: max,
		},
		{
			Algorithm: NewLogarithmicTimeoutAlgorithm(expiryLeewayFactor, timeout, expiryDelta),
		},
	})

	return NewIfExpiresTimeoutAlgorithm(alg, min)
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
	ctx, cancel := pto.alg.ContextWithTimeout(ctx, nil)
	defer cancel()

	return pto.delegate.DeviceCodeAuth(ctx, opts...)
}

func (pto *publicTimeoutOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...DeviceCodeExchangeOption) (*Token, error) {
	ctx, cancel := pto.alg.ContextWithTimeout(ctx, nil)
	defer cancel()

	return pto.delegate.DeviceCodeExchange(ctx, deviceCode, opts...)
}

func (pto *publicTimeoutOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	ctx, cancel := pto.alg.ContextWithTimeout(ctx, t)
	defer cancel()

	return pto.delegate.RefreshToken(ctx, t, opts...)
}

type privateTimeoutOperations struct {
	*publicTimeoutOperations
	delegate PrivateOperations
}

func (pto *privateTimeoutOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	ctx, cancel := pto.alg.ContextWithTimeout(ctx, nil)
	defer cancel()

	return pto.delegate.AuthCodeExchange(ctx, code, opts...)
}

func (pto *privateTimeoutOperations) ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error) {
	ctx, cancel := pto.alg.ContextWithTimeout(ctx, nil)
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
