package provider

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// AuthCodeURLConfig is the component of *oauth2.Config required for generating
// authorization code URLs.
type AuthCodeURLConfig interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
}

// AuthCodeURLConfigBuilder creates AuthCodeURLConfigs.
type AuthCodeURLConfigBuilder interface {
	// WithRedirectURL sets the redirect URL for the config.
	WithRedirectURL(redirectURL string) AuthCodeURLConfigBuilder

	// WithScopes sets the scopes for the config.
	WithScopes(scopes ...string) AuthCodeURLConfigBuilder

	// Build creates an AuthCodeURLConfig from the current configuration.
	Build() AuthCodeURLConfig
}

// ExchangeConfig is the component of *oauth2.Config required to exchange an
// authorization code for a token.
type ExchangeConfig interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource
}

// ExchangeConfigBuilder creates ExchangeConfigs.
type ExchangeConfigBuilder interface {
	// WithHTTPClient uses the given HTTP client to perform the exchange.
	WithHTTPClient(client *http.Client) ExchangeConfigBuilder

	// WithRedirectURL sets the redirect URL for the config.
	WithRedirectURL(redirectURL string) ExchangeConfigBuilder

	// Build creates an ExchangeConfig from the current configuration.
	Build() ExchangeConfig
}

// Provider represents an integration with a particular OAuth provider using the
// authorization code grant.
type Provider interface {
	// Version is the revision of this provider vis-a-vis the options it
	// supports.
	Version() int

	// NewAuthCodeURLConfigBuilder creates a config builder automatically scoped
	// to this provider with the specified options.
	NewAuthCodeURLConfigBuilder(clientID string) AuthCodeURLConfigBuilder

	// NewExchangeConfigBuilder creates a new config builder for token exchange.
	NewExchangeConfigBuilder(clientID, clientSecret string) ExchangeConfigBuilder
}

type factoryFunc func(vsn int, opts map[string]string) (Provider, error)

var registry = make(map[string]factoryFunc)

// New looks up a provider with the given name and configures it according to
// the specified options.
func New(name string, opts map[string]string) (Provider, error) {
	return NewAt(name, -1, opts)
}

// NewAt looks up a provider with the given name at the given version and
// configures it according to the specified options.
func NewAt(name string, vsn int, opts map[string]string) (Provider, error) {
	p, found := registry[name]
	if !found {
		return nil, ErrNoSuchProvider
	}

	return p(vsn, opts)
}
