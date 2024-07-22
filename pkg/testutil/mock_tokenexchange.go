package testutil

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/interop"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"golang.org/x/oauth2"
)

func StaticMockTokenExchange(token *provider.Token) MockTokenExchangeFunc {
	return func(_ *provider.Token, _ *provider.TokenExchangeOptions) (*provider.Token, error) {
		return token, nil
	}
}

func AmendTokenMockTokenExchange(get MockTokenExchangeFunc, amend func(token *provider.Token) error) MockTokenExchangeFunc {
	return func(t *provider.Token, opts *provider.TokenExchangeOptions) (*provider.Token, error) {
		token, err := get(t, opts)
		if err != nil {
			return nil, err
		}

		if err := amend(token); err != nil {
			return nil, err
		}

		return token, nil
	}
}

func ExpiringMockTokenExchange(fn MockTokenExchangeFunc, duration time.Duration) MockTokenExchangeFunc {
	return AmendTokenMockTokenExchange(fn, func(t *provider.Token) error {
		t.Expiry = time.Now().Add(duration)
		return nil
	})
}

func ExpiringMockTokenExchangeStep(fn MockTokenExchangeFunc, step func(i int) (time.Duration, error)) MockTokenExchangeFunc {
	var i int32

	return AmendTokenMockTokenExchange(fn, func(t *provider.Token) error {
		exp, err := step(int(atomic.AddInt32(&i, 1)))
		if err != nil {
			return err
		}

		t.Expiry = time.Now().Add(exp)
		return nil
	})
}

func IncrementMockTokenExchange(prefix string) MockTokenExchangeFunc {
	var i int32

	return func(_ *provider.Token, _ *provider.TokenExchangeOptions) (*provider.Token, error) {
		t := &oauth2.Token{
			AccessToken: fmt.Sprintf("%s%d", prefix, atomic.AddInt32(&i, 1)),
		}
		return &provider.Token{Token: t}, nil
	}
}

func FilterMockTokenExchange(fn MockTokenExchangeFunc, filters ...func(t *provider.Token, opts *provider.TokenExchangeOptions) bool) MockTokenExchangeFunc {
	return func(t *provider.Token, opts *provider.TokenExchangeOptions) (*provider.Token, error) {
		for _, filter := range filters {
			if !filter(t, opts) {
				return nil, MockErrorResponse(http.StatusForbidden, &interop.JSONError{Error: "access_denied"})
			}
		}

		return fn(t, opts)
	}
}

func RestrictMockTokenExchange(m map[string]MockTokenExchangeFunc) MockTokenExchangeFunc {
	return func(t *provider.Token, opts *provider.TokenExchangeOptions) (*provider.Token, error) {
		found := false
		var name string
		var fn MockTokenExchangeFunc
		for name, fn = range m {
			if strings.HasPrefix(t.AccessToken, name) {
				found = true
				break
			}
		}
		if !found {
			return nil, MockErrorResponse(http.StatusForbidden, &interop.JSONError{Error: "access_denied"})
		}

		return fn(t, opts)
	}
}
