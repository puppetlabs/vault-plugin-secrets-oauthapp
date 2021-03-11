package provider

import (
	"context"
	"net/url"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/grant/devicecode"
	"golang.org/x/oauth2"
)

// Endpoint is an extension of oauth2.Endpoint that also provides information
// about other URLs.
type Endpoint struct {
	oauth2.Endpoint

	DeviceURL string
}

// Token is an extension of *oauth2.Token that also provides complementary data
// to store (usually from the token's own raw data).
type Token struct {
	*oauth2.Token `json:",inline"`

	ExtraData map[string]interface{} `json:"extra_data,omitempty"`
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
	Scopes []string
}

type DeviceCodeAuthOption interface {
	ApplyToDeviceCodeAuthOptions(target *DeviceCodeAuthOptions)
}

func (o *DeviceCodeAuthOptions) ApplyOptions(opts []DeviceCodeAuthOption) {
	for _, opt := range opts {
		opt.ApplyToDeviceCodeAuthOptions(o)
	}
}

// PublicOperations defines the operations for a client that only require
// knowledge of the client ID.
type PublicOperations interface {
	AuthCodeURL(state string, opts ...AuthCodeURLOption) (string, bool)
	DeviceCodeAuth(ctx context.Context, opts ...DeviceCodeAuthOption) (*devicecode.Auth, bool, error)
	DeviceCodeExchange(ctx context.Context, deviceCode string) (*Token, error)
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

	// RefreshToken performs a refresh token flow request.
	RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error)

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
