package provider

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	gooidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"golang.org/x/oauth2"
)

const (
	oidcExtraDataFieldIDToken       = "id_token"
	oidcExtraDataFieldIDTokenClaims = "id_token_claims"
	oidcExtraDataFieldUserInfo      = "user_info"

	oidcExchangeConfigOptionNonce = "nonce"
)

var (
	ErrOIDCMissingIDToken = errors.New("provider: oidc: missing ID token in response")
	ErrOIDCNonceMismatch  = errors.New("provider: oidc: nonce does not match")
)

func init() {
	GlobalRegistry.MustRegister("oidc", OIDCFactory)
}

type oidcExchangeConfig struct {
	delegate        *basicExchangeConfig
	p               *gooidc.Provider
	nonce           string
	extraDataFields []string
}

func (c *oidcExchangeConfig) verifyUpdateToken(ctx context.Context, t *Token) error {
	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok {
		return ErrOIDCMissingIDToken
	}

	idToken, err := c.p.Verifier(&gooidc.Config{ClientID: c.delegate.config.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("provider: oidc: verification error: %+v", err)
	}

	// If nonce is configured, make sure it matches the nonce in
	// the ID token.  It is not configured when refresh_token is
	// sent in from an external source.
	if len(c.nonce) > 0 &&
		(subtle.ConstantTimeEq(int32(len(idToken.Nonce)), int32(len(c.nonce))) == 0 ||
			subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(c.nonce)) == 0) {
		return ErrOIDCNonceMismatch
	}

	if len(c.extraDataFields) > 0 {
		t.ExtraData = make(map[string]interface{})

		for _, field := range c.extraDataFields {
			switch field {
			case oidcExtraDataFieldIDToken:
				t.ExtraData[field] = rawIDToken
			case oidcExtraDataFieldIDTokenClaims:
				claims := make(map[string]interface{})
				if err := idToken.Claims(&claims); err != nil {
					return fmt.Errorf("provider: oidc: error parsing token claims: %+v", err)
				}

				t.ExtraData[field] = claims
			case oidcExtraDataFieldUserInfo:
				userInfo, err := c.p.UserInfo(ctx, c.delegate.config.TokenSource(ctx, t.Token))
				if err != nil {
					return fmt.Errorf("provider: oidc: error fetching user info: %+v", err)
				}

				claims := make(map[string]interface{})
				if err := userInfo.Claims(&claims); err != nil {
					return fmt.Errorf("provider: oidc: error parsing user info: %+v", err)
				}

				t.ExtraData[field] = claims
			}
		}
	}

	return nil
}

func (c *oidcExchangeConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*Token, error) {
	t, err := c.delegate.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}

	if err := c.verifyUpdateToken(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

func (c *oidcExchangeConfig) Refresh(ctx context.Context, t *Token) (*Token, error) {
	t, err := c.delegate.Refresh(ctx, t)
	if err != nil {
		return nil, err
	}

	if err := c.verifyUpdateToken(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

type oidcExchangeConfigBuilder struct {
	config          *oauth2.Config
	p               *gooidc.Provider
	nonce           string
	extraDataFields []string
}

func (cb *oidcExchangeConfigBuilder) WithOption(name, value string) ExchangeConfigBuilder {
	if name == oidcExchangeConfigOptionNonce {
		cb.nonce = value
	}

	return cb
}

func (cb *oidcExchangeConfigBuilder) WithRedirectURL(redirectURL string) ExchangeConfigBuilder {
	cb.config.RedirectURL = redirectURL
	return cb
}

func (cb *oidcExchangeConfigBuilder) Build() ExchangeConfig {
	return &oidcExchangeConfig{
		delegate: &basicExchangeConfig{
			config: cb.config,
		},
		p:               cb.p,
		extraDataFields: cb.extraDataFields,
	}
}

type oidc struct {
	vsn             int
	p               *gooidc.Provider
	authStyle       oauth2.AuthStyle
	extraDataFields []string
}

func (o *oidc) endpoint() oauth2.Endpoint {
	ep := o.p.Endpoint()
	ep.AuthStyle = o.authStyle
	return ep
}

func (o *oidc) Version() int {
	return o.vsn
}

func (o *oidc) NewAuthCodeURLConfigBuilder(clientID string) AuthCodeURLConfigBuilder {
	return NewConformingAuthCodeURLConfigBuilder(o.endpoint(), clientID)
}

func (o *oidc) NewExchangeConfigBuilder(clientID, clientSecret string) ExchangeConfigBuilder {
	return &oidcExchangeConfigBuilder{
		config: &oauth2.Config{
			Endpoint:     o.endpoint(),
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
		p:               o.p,
		extraDataFields: o.extraDataFields,
	}
}

func OIDCFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 1)

	switch vsn {
	case 1:
	default:
		return nil, ErrNoProviderWithVersion
	}

	if opts["issuer_url"] == "" {
		return nil, &OptionError{Option: "issuer_url", Message: "issuer URL is required"}
	}

	delegate, err := gooidc.NewProvider(ctx, opts["issuer_url"])
	if err != nil {
		return nil, &OptionError{Option: "issuer_url", Message: fmt.Sprintf("error creating OIDC provider with given issuer URL: %+v", err)}
	}

	// For some reason, the upstream provider does not check the
	// "token_endpoint_auth_methods_supported" value.
	authStyle := delegate.Endpoint().AuthStyle
	if authStyle == oauth2.AuthStyleAutoDetect {
		var metadata struct {
			TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		}
		if err := delegate.Claims(&metadata); err != nil {
			return nil, &OptionError{Option: "issuer_url", Message: fmt.Sprintf("error decoding OIDC provider metadata: %+v", err)}
		}

		if strutil.StrListContains(metadata.TokenEndpointAuthMethodsSupported, "client_secret_post") {
			authStyle = oauth2.AuthStyleInParams
		} else {
			authStyle = oauth2.AuthStyleInHeader
		}
	}

	p := &oidc{
		vsn:       vsn,
		p:         delegate,
		authStyle: authStyle,
	}

	if opts["extra_data_fields"] != "" {
		fields, err := parseutil.ParseCommaStringSlice(opts["extra_data_fields"])
		if err != nil {
			return nil, &OptionError{Option: "extra_data_fields", Message: fmt.Sprintf("invalid format (expected a comma-separated list): %+v", err)}
		}

		for _, field := range fields {
			switch field {
			case oidcExtraDataFieldIDToken, oidcExtraDataFieldIDTokenClaims, oidcExtraDataFieldUserInfo:
			default:
				return nil, &OptionError{Option: "extra_data_fields", Message: fmt.Sprintf("unknown extra data field %q", field)}
			}
		}

		p.extraDataFields = fields
	}

	return p, nil
}
