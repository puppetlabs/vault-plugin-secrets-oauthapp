package provider

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	gooidc "github.com/coreos/go-oidc"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/devicecode"
	"golang.org/x/oauth2"
)

const (
	oidcExtraDataFieldIDToken       = "id_token"
	oidcExtraDataFieldIDTokenClaims = "id_token_claims"
	oidcExtraDataFieldUserInfo      = "user_info"
)

var (
	ErrOIDCMissingIDToken = errors.New("oidc: missing ID token in response")
	ErrOIDCNonceMismatch  = errors.New("oidc: nonce does not match")
)

func init() {
	GlobalRegistry.MustRegister("oidc", OIDCFactory)
}

type oidcOperations struct {
	delegate        *basicOperations
	p               *gooidc.Provider
	extraDataFields []string
}

func (oo *oidcOperations) verifyUpdateIDToken(ctx context.Context, t *Token) error {
	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ErrOIDCMissingIDToken
	}

	idToken, err := oo.p.Verifier(&gooidc.Config{ClientID: oo.delegate.clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("oidc: verification error: %w", err)
	}

	// If nonce is configured, make sure it matches the nonce in the ID token.
	// It is not configured when refresh_token is sent in from an external
	// source.
	if nonce := t.ProviderOptions["nonce"]; nonce != "" &&
		(subtle.ConstantTimeEq(int32(len(idToken.Nonce)), int32(len(nonce))) == 0 ||
			subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) == 0) {
		return ErrOIDCNonceMismatch
	}

	for _, field := range oo.extraDataFields {
		switch field {
		case oidcExtraDataFieldIDToken:
			t.ExtraData[field] = rawIDToken
		case oidcExtraDataFieldIDTokenClaims:
			claims := make(map[string]interface{})
			if err := idToken.Claims(&claims); err != nil {
				return fmt.Errorf("oidc: error parsing token claims: %w", err)
			}

			t.ExtraData[field] = claims
		}
	}

	return nil
}

func (oo *oidcOperations) copyIDToken(ctx context.Context, p, n *Token) {
	for _, field := range oo.extraDataFields {
		switch field {
		case oidcExtraDataFieldIDToken, oidcExtraDataFieldIDTokenClaims:
			n.ExtraData[field] = p.ExtraData[field]
		}
	}
}

func (oo *oidcOperations) updateUserInfo(ctx context.Context, t *Token) error {
	for _, field := range oo.extraDataFields {
		if field != oidcExtraDataFieldUserInfo {
			continue
		}

		userInfo, err := oo.p.UserInfo(ctx, oauth2.StaticTokenSource(t.Token))
		if err != nil {
			return fmt.Errorf("oidc: error fetching user info: %w", err)
		}

		claims := make(map[string]interface{})
		if err := userInfo.Claims(&claims); err != nil {
			return fmt.Errorf("oidc: error parsing user info: %w", err)
		}

		t.ExtraData[field] = claims
		break
	}

	return nil
}

func (oo *oidcOperations) AuthCodeURL(state string, opts ...AuthCodeURLOption) (string, bool) {
	opts = append([]AuthCodeURLOption{WithScopes{"openid"}}, opts...)
	return oo.delegate.AuthCodeURL(state, opts...)
}

func (oo *oidcOperations) DeviceCodeAuth(ctx context.Context, opts ...DeviceCodeAuthOption) (*devicecode.Auth, bool, error) {
	opts = append([]DeviceCodeAuthOption{WithScopes{"openid"}}, opts...)
	return oo.delegate.DeviceCodeAuth(ctx, opts...)
}

func (oo *oidcOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...DeviceCodeExchangeOption) (*Token, error) {
	t, err := oo.delegate.DeviceCodeExchange(ctx, deviceCode, opts...)
	if err != nil {
		return nil, err
	}

	if t.ExtraData == nil {
		t.ExtraData = make(map[string]interface{})
	}

	// Nonce doesn't even make sense here, so just make sure it isn't set.
	delete(t.ProviderOptions, "nonce")

	if err := oo.verifyUpdateIDToken(ctx, t); err != nil {
		return nil, errmark.MarkUser(err)
	}

	if err := oo.updateUserInfo(ctx, t); err != nil {
		return nil, errmark.MarkUser(err)
	}

	return t, nil
}

func (oo *oidcOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	t, err := oo.delegate.AuthCodeExchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}

	if t.ExtraData == nil {
		t.ExtraData = make(map[string]interface{})
	}

	if err := oo.verifyUpdateIDToken(ctx, t); err != nil {
		return nil, errmark.MarkUser(err)
	}

	if err := oo.updateUserInfo(ctx, t); err != nil {
		return nil, errmark.MarkUser(err)
	}

	// Nonce is only to be used once, so do not persist with the token.
	delete(t.ProviderOptions, "nonce")

	return t, nil
}

func (oo *oidcOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	nt, err := oo.delegate.RefreshToken(ctx, t, opts...)
	if err != nil {
		return nil, err
	}

	if nt.ExtraData == nil {
		nt.ExtraData = make(map[string]interface{})
	}

	// Per OpenID Connect Core 1.0 § 12.2
	// (https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse),
	// providing an ID token as part of a refresh is optional. We will only
	// revalidate the token if a new one is provided.
	if rawIDToken, ok := nt.Extra("id_token").(string); ok && rawIDToken != "" {
		if err := oo.verifyUpdateIDToken(ctx, nt); err != nil {
			return nil, errmark.MarkUser(err)
		}
	} else {
		oo.copyIDToken(ctx, t, nt)
	}

	if err := oo.updateUserInfo(ctx, nt); err != nil {
		return nil, errmark.MarkUser(err)
	}

	// Nonce is only to be used once, so do not persist with the token.
	delete(nt.ProviderOptions, "nonce")

	return nt, nil
}

func (oo *oidcOperations) ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error) {
	return oo.delegate.ClientCredentials(ctx, opts...)
}

type oidc struct {
	vsn             int
	p               *gooidc.Provider
	authStyle       oauth2.AuthStyle
	deviceURL       string
	extraDataFields []string
}

func (o *oidc) endpointFactory(opts map[string]string) Endpoint {
	ep := Endpoint{
		Endpoint:  o.p.Endpoint(),
		DeviceURL: o.deviceURL,
	}
	ep.AuthStyle = o.authStyle
	return ep
}

func (o *oidc) Version() int {
	return o.vsn
}

func (o *oidc) Public(clientID string) PublicOperations {
	return o.Private(clientID, "")
}

func (o *oidc) Private(clientID, clientSecret string) PrivateOperations {
	return &oidcOperations{
		delegate: &basicOperations{
			vsn:             o.vsn,
			endpointFactory: o.endpointFactory,
			clientID:        clientID,
			clientSecret:    clientSecret,
		},
		p:               o.p,
		extraDataFields: o.extraDataFields,
	}
}

func newOIDC(ctx context.Context, vsn int, issuerURL string, extraDataFields []string) (*oidc, error) {
	delegate, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("error creating OIDC provider with given issuer URL: %w", err)
	}

	var metadata struct {
		DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := delegate.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("error decoding OIDC provider metadata: %w", err)
	}

	// For some reason, the upstream provider does not check the
	// "token_endpoint_auth_methods_supported" value.
	authStyle := delegate.Endpoint().AuthStyle
	if authStyle == oauth2.AuthStyleAutoDetect {
		if strutil.StrListContains(metadata.TokenEndpointAuthMethodsSupported, "client_secret_post") {
			authStyle = oauth2.AuthStyleInParams
		} else {
			authStyle = oauth2.AuthStyleInHeader
		}
	}

	return &oidc{
		vsn:             vsn,
		p:               delegate,
		deviceURL:       metadata.DeviceAuthorizationEndpoint,
		authStyle:       authStyle,
		extraDataFields: extraDataFields,
	}, nil
}

func OIDCFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 1)

	switch vsn {
	case 1:
	default:
		return nil, ErrNoProviderWithVersion
	}

	if opts["issuer_url"] == "" {
		return nil, &OptionError{Option: "issuer_url", Cause: fmt.Errorf("issuer URL is required")}
	}

	fields, err := parseOIDCExtraDataFields(opts["extra_data_fields"])
	if err != nil {
		return nil, &OptionError{Option: "extra_data_fields", Cause: err}
	}

	p, err := newOIDC(ctx, vsn, opts["issuer_url"], fields)
	if err != nil {
		return nil, &OptionError{Option: "issuer_url", Cause: err}
	}

	return p, nil
}

func parseOIDCExtraDataFields(data string) ([]string, error) {
	if data == "" {
		return nil, nil
	}

	fields, err := parseutil.ParseCommaStringSlice(data)
	if err != nil {
		return nil, fmt.Errorf("invalid format (expected a comma-separated list): %w", err)
	}

	for _, field := range fields {
		switch field {
		case oidcExtraDataFieldIDToken, oidcExtraDataFieldIDTokenClaims, oidcExtraDataFieldUserInfo:
		default:
			return nil, fmt.Errorf("unknown extra data field %q", field)
		}
	}

	return fields, nil
}
