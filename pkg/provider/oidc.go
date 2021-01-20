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
	*basicOperations
	p               *gooidc.Provider
	extraDataFields []string
}

func (oo *oidcOperations) verifyUpdateIDToken(ctx context.Context, t *Token, nonce string) error {
	rawIDToken, ok := t.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ErrOIDCMissingIDToken
	}

	idToken, err := oo.p.Verifier(&gooidc.Config{ClientID: oo.basicOperations.base.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("oidc: verification error: %w", err)
	}

	// If nonce is configured, make sure it matches the nonce in the ID token.
	// It is not configured when refresh_token is sent in from an external
	// source.
	if nonce != "" &&
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

func (oo *oidcOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	o := &AuthCodeExchangeOptions{}
	o.ApplyOptions(opts)

	t, err := oo.basicOperations.AuthCodeExchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}

	if t.ExtraData == nil {
		t.ExtraData = make(map[string]interface{})
	}

	if err := oo.verifyUpdateIDToken(ctx, t, o.ProviderOptions["nonce"]); err != nil {
		return nil, errmark.MarkUser(err)
	}

	if err := oo.updateUserInfo(ctx, t); err != nil {
		return nil, errmark.MarkUser(err)
	}

	return t, nil
}

func (oo *oidcOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	o := &RefreshTokenOptions{}
	o.ApplyOptions(opts)

	nt, err := oo.basicOperations.RefreshToken(ctx, t, opts...)
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
		if err := oo.verifyUpdateIDToken(ctx, nt, o.ProviderOptions["nonce"]); err != nil {
			return nil, errmark.MarkUser(err)
		}
	} else {
		oo.copyIDToken(ctx, t, nt)
	}

	if err := oo.updateUserInfo(ctx, t); err != nil {
		return nil, errmark.MarkUser(err)
	}

	return nt, nil
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

func (o *oidc) Public(clientID string) PublicOperations {
	return o.Private(clientID, "")
}

func (o *oidc) Private(clientID, clientSecret string) PrivateOperations {
	return &oidcOperations{
		basicOperations: &basicOperations{
			base: &oauth2.Config{
				Endpoint:     o.endpoint(),
				ClientID:     clientID,
				ClientSecret: clientSecret,
			},
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
