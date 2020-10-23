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

// TokenConfig is the component of *oauth2/clientcredentials.Config required
// for retrieving a token via 2-legged OAuth
type TokenConfig interface {
	Token(ctx context.Context) (*oauth2.Token, error)
	TokenSource(ctx context.Context) oauth2.TokenSource
}

// TokenConfigBuilder creates TokenConfigs.
type TokenConfigBuilder interface {
	// WithHTTPClient uses the given HTTP client to perform the exchange.
	WithHTTPClient(client *http.Client) TokenConfigBuilder

	// WithScopes sets the scopes for the config.
	WithScopes(scopes ...string) TokenConfigBuilder

	// Build creates an TokenConfig from the current configuration.
	Build() TokenConfig
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

	// NewTokenConfigBuilder creates a new config builder for 2-legged token exchange.
	NewTokenConfigBuilder(clientID, clientSecret string) (TokenConfigBuilder, error)

	// IsAuthorizationRequired returns true if authorization is required (i.e. 3-legged OAuth)
	// or returns false if it's not required (i.e. 2-legged OAuth)
	IsAuthorizationRequired() bool
}

var GlobalRegistry = NewRegistry()
