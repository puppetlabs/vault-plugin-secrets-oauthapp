package provider

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// Token is an extension of *oauth2.Token that also provides complementary data
// to store (usually from the token's own raw data).
type Token struct {
	*oauth2.Token `json:",inline"`

	ExtraData map[string]interface{} `json:"extra_data,omitempty"`
}

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
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*Token, error)
	Refresh(ctx context.Context, t *Token) (*Token, error)
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

const VersionLatest = -1

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

var GlobalRegistry = NewRegistry()
