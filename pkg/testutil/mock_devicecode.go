package testutil

import (
	"net/http"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/devicecode"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/interop"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

func StaticMockDeviceCodeAuth(auth *devicecode.Auth) MockDeviceCodeAuthFunc {
	return func(_ *provider.DeviceCodeAuthOptions) (*devicecode.Auth, error) {
		return auth, nil
	}
}

func AmendTokenMockDeviceCodeExchange(get MockDeviceCodeExchangeFunc, amend func(token *provider.Token) error) MockDeviceCodeExchangeFunc {
	return func(candidate string, opts *provider.DeviceCodeExchangeOptions) (*provider.Token, error) {
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

func ErrorMockDeviceCodeExchange(errType string) MockDeviceCodeExchangeFunc {
	return func(_ string, _ *provider.DeviceCodeExchangeOptions) (*provider.Token, error) {
		return nil, MockErrorResponse(http.StatusUnauthorized, &interop.JSONError{Error: errType})
	}
}

var (
	AuthorizationPendingErrorMockDeviceCodeExchange = ErrorMockDeviceCodeExchange("authorization_pending")
	ExpiredTokenErrorMockDeviceCodeExchange         = ErrorMockDeviceCodeExchange("expired_token")
	SlowDownErrorMockDeviceCodeExchange             = ErrorMockDeviceCodeExchange("slow_down")
)
