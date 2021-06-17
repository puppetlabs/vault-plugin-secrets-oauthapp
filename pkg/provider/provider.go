package provider

import (
	"context"
	"net/url"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/devicecode"
	"golang.org/x/oauth2"
)

// Endpoint is an extension of oauth2.Endpoint that also provides information
// about other URLs.
type Endpoint struct {
	oauth2.Endpoint

	DeviceURL string
}

// EndpointFactoryFunc returns an Endpoint given some provider configuration.
type EndpointFactoryFunc func(opts map[string]string) Endpoint

// StaticEndpointFactory returns an EndpointFactoryFunc for a static endpoint
// configuration that does not take provider options.
func StaticEndpointFactory(endpoint Endpoint) EndpointFactoryFunc {
	return func(opts map[string]string) Endpoint {
		return endpoint
	}
}

// Token is an extension of *oauth2.Token that also provides complementary data
// to store (usually from the token's own raw data).
type Token struct {
	*oauth2.Token `json:",inline"`

	ExtraData map[string]interface{} `json:"extra_data,omitempty"`

	// ProviderVersion is the version of the provider that last updated this
	// token. It can be used to upgrade the provider options before handing off
	// to methods that expect versions to be synchronized with the plugin
	// provider version.
	//
	// May be unspecified. If not specified, provider options must be treated as
	// opaque data.
	ProviderVersion int `json:"provider_version,omitempty"`

	// ProviderOptions are the set of persistent options to use for this token
	// when configuring a provider.
	ProviderOptions map[string]string `json:"provider_options,omitempty"`
}

// AuthCodeURLOptions are options for the AuthCodeURL operation.
type AuthCodeURLOptions struct {
	RedirectURL     string
	Scopes          []string
	AuthCodeOptions []oauth2.AuthCodeOption
	ProviderOptions map[string]string
}

type AuthCodeURLOption interface {
	ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions)
}

func (o *AuthCodeURLOptions) ApplyOptions(opts []AuthCodeURLOption) {
	for _, opt := range opts {
		opt.ApplyToAuthCodeURLOptions(o)
	}
}

// DeviceCodeAuthOptions are options for the DeviceCodeAuth operation.
type DeviceCodeAuthOptions struct {
	Scopes          []string
	ProviderOptions map[string]string
}

type DeviceCodeAuthOption interface {
	ApplyToDeviceCodeAuthOptions(target *DeviceCodeAuthOptions)
}

func (o *DeviceCodeAuthOptions) ApplyOptions(opts []DeviceCodeAuthOption) {
	for _, opt := range opts {
		opt.ApplyToDeviceCodeAuthOptions(o)
	}
}

// DeviceCodeExchangeOptions are options for the DeviceCodeExchange operation.
type DeviceCodeExchangeOptions struct {
	ProviderOptions map[string]string
}

type DeviceCodeExchangeOption interface {
	ApplyToDeviceCodeExchangeOptions(target *DeviceCodeExchangeOptions)
}

func (o *DeviceCodeExchangeOptions) ApplyOptions(opts []DeviceCodeExchangeOption) {
	for _, opt := range opts {
		opt.ApplyToDeviceCodeExchangeOptions(o)
	}
}

// PublicOperations defines the operations for a client that only require
// knowledge of the client ID.
type PublicOperations interface {
	// AuthCodeURL returns a URL to send a user to for initial authentication.
	//
	// If this provider does not define an authorization code endpoint URL, this
	// method returns false.
	AuthCodeURL(state string, opts ...AuthCodeURLOption) (string, bool)

	// DeviceCodeAuth performs the RFC 8628 device code authorization operation.
	//
	// If this provider does not support device code authorization, this method
	// returns false.
	DeviceCodeAuth(ctx context.Context, opts ...DeviceCodeAuthOption) (*devicecode.Auth, bool, error)

	// DeviceCodeExchange performs the RFC 8628 device code exchange operation
	// once, without polling.
	DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...DeviceCodeExchangeOption) (*Token, error)

	// RefreshToken performs a refresh token flow request.
	//
	// This method does not check the expiration of the token. It forces a
	// refresh when invoked.
	//
	// Depending on the source of the token, this method may require the client
	// secret. However, for implicit and device code grants, it only requires
	// the client ID.
	RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error)
}

// AuthCodeExchangeOptions are options for the AuthCodeExchange operation.
type AuthCodeExchangeOptions struct {
	RedirectURL     string
	AuthCodeOptions []oauth2.AuthCodeOption
	ProviderOptions map[string]string
}

type AuthCodeExchangeOption interface {
	ApplyToAuthCodeExchangeOptions(target *AuthCodeExchangeOptions)
}

func (o *AuthCodeExchangeOptions) ApplyOptions(opts []AuthCodeExchangeOption) {
	for _, opt := range opts {
		opt.ApplyToAuthCodeExchangeOptions(o)
	}
}

// RefreshTokenOptions are options for the RefreshToken operation.
type RefreshTokenOptions struct {
	ProviderOptions map[string]string
}

type RefreshTokenOption interface {
	ApplyToRefreshTokenOptions(target *RefreshTokenOptions)
}

func (o *RefreshTokenOptions) ApplyOptions(opts []RefreshTokenOption) {
	for _, opt := range opts {
		opt.ApplyToRefreshTokenOptions(o)
	}
}

// ClientCredentialsOptions are options for the ClientCredentials operation.
type ClientCredentialsOptions struct {
	Scopes          []string
	EndpointParams  url.Values
	ProviderOptions map[string]string
}

type ClientCredentialsOption interface {
	ApplyToClientCredentialsOptions(target *ClientCredentialsOptions)
}

func (o *ClientCredentialsOptions) ApplyOptions(opts []ClientCredentialsOption) {
	for _, opt := range opts {
		opt.ApplyToClientCredentialsOptions(o)
	}
}

// PrivateOperations defines the operations for a client that require knowledge
// of the client ID and client secret.
type PrivateOperations interface {
	PublicOperations

	// AuthCodeExchange performs an authorization code flow exchange request.
	AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error)

	// ClientCredentials performs a client credentials flow request.
	ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error)
}

const VersionLatest = -1

// Provider represents an integration with a particular OAuth provider using the
// authorization code grant.
type Provider interface {
	// Version is the revision of this provider vis-a-vis the options it
	// supports.
	Version() int

	// Public returns a view of the operations for this provider for the given
	// client ID.
	Public(clientID string) PublicOperations

	// Private returns a complete set of the operations for this provider for
	// the given client ID and client secret.
	Private(clientID, clientSecret string) PrivateOperations
}

var GlobalRegistry = NewRegistry()
