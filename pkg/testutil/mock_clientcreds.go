package testutil

import (
	"fmt"
	"sync/atomic"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"golang.org/x/oauth2"
)

func StaticMockClientCredentials(token *provider.Token) MockClientCredentialsFunc {
	return func(_ *provider.ClientCredentialsOptions) (*provider.Token, error) {
		return token, nil
	}
}

func AmendTokenMockClientCredentials(get MockClientCredentialsFunc, amend func(token *provider.Token) error) MockClientCredentialsFunc {
	return func(opts *provider.ClientCredentialsOptions) (*provider.Token, error) {
		token, err := get(opts)
		if err != nil {
			return nil, err
		}

		if err := amend(token); err != nil {
			return nil, err
		}

		return token, nil
	}
}

func RandomMockClientCredentials(_ *provider.ClientCredentialsOptions) (*provider.Token, error) {
	t := &oauth2.Token{
		AccessToken: randomToken(10),
	}
	return &provider.Token{Token: t}, nil
}

func IncrementMockClientCredentials(prefix string) MockClientCredentialsFunc {
	var i int32

	return func(_ *provider.ClientCredentialsOptions) (*provider.Token, error) {
		t := &oauth2.Token{
			AccessToken: fmt.Sprintf("%s%d", prefix, atomic.AddInt32(&i, 1)),
		}
		return &provider.Token{Token: t}, nil
	}
}
