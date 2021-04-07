package testutil

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/interop"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
	"golang.org/x/oauth2"
)

func StaticMockAuthCodeExchange(token *provider.Token) MockAuthCodeExchangeFunc {
	return func(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		return token, nil
	}
}

func AmendTokenMockAuthCodeExchange(get MockAuthCodeExchangeFunc, amend func(token *provider.Token) error) MockAuthCodeExchangeFunc {
	return func(candidate string, opts *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		token, err := get(candidate, opts)
		if err != nil {
			return nil, err
		}

		if err := amend(token); err != nil {
			return nil, err
		}

		return token, nil
	}
}

func ExpiringMockAuthCodeExchange(fn MockAuthCodeExchangeFunc, duration time.Duration) MockAuthCodeExchangeFunc {
	return AmendTokenMockAuthCodeExchange(fn, func(t *provider.Token) error {
		t.Expiry = time.Now().Add(duration)
		return nil
	})
}

func RefreshableMockAuthCodeExchange(fn MockAuthCodeExchangeFunc, step func(i int) (time.Duration, error)) MockAuthCodeExchangeFunc {
	refreshToken := randomToken(40)
	var i int32

	return AmendTokenMockAuthCodeExchange(fn, func(t *provider.Token) error {
		exp, err := step(int(atomic.AddInt32(&i, 1)))
		if err != nil {
			return err
		}

		t.RefreshToken = refreshToken
		t.Expiry = time.Now().Add(exp)
		return nil
	})
}

func RandomMockAuthCodeExchange(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
	t := &oauth2.Token{
		AccessToken: randomToken(10),
	}
	return &provider.Token{Token: t}, nil
}

func IncrementMockAuthCodeExchange(prefix string) MockAuthCodeExchangeFunc {
	var i int32

	return func(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		t := &oauth2.Token{
			AccessToken: fmt.Sprintf("%s%d", prefix, atomic.AddInt32(&i, 1)),
		}
		return &provider.Token{Token: t}, nil
	}
}

func ErrorMockAuthCodeExchange(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
	return nil, MockErrorResponse(http.StatusUnauthorized, &interop.JSONError{Error: "unauthorized_client"})
}

func RestrictMockAuthCodeExchange(m map[string]MockAuthCodeExchangeFunc) MockAuthCodeExchangeFunc {
	return func(token string, opts *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		fn, found := m[token]
		if !found {
			fn = ErrorMockAuthCodeExchange
		}

		return fn(token, opts)
	}
}
