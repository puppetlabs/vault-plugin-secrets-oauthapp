// TODO: We should upgrade credential keys to use a cryptographically secure
// hash algorithm.
/* #nosec G401 G505 */

package backend

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/oauth2ext/devicecode"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"golang.org/x/oauth2"
)

// credGrantType returns the grant type to be used for a given update operation.
func credGrantType(data *framework.FieldData) string {
	if v, ok := data.GetOk("grant_type"); ok {
		return v.(string)
	} else if _, ok := data.GetOk("refresh_token"); ok {
		return "refresh_token"
	}

	return "authorization_code"
}

// credUpdateGrantHandlers implement individual handlers for the different grant
// types that the update operation supports.
var credUpdateGrantHandlers = map[string]func(b *backend) framework.OperationFunc{
	"authorization_code": func(b *backend) framework.OperationFunc { return b.credsUpdateAuthorizationCodeOperation },
	"refresh_token":      func(b *backend) framework.OperationFunc { return b.credsUpdateRefreshTokenOperation },
	devicecode.GrantType: func(b *backend) framework.OperationFunc { return b.credsUpdateDeviceCodeOperation },
}

// credGrantTypes returns the list of supported grant types for credentials for
// schema purposes.
func credGrantTypes() (types []interface{}) {
	for k := range credUpdateGrantHandlers {
		types = append(types, k)
	}
	return
}

func (b *backend) credsReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	expiryDelta := time.Duration(data.Get("minimum_seconds").(int)) * time.Second

	entry, err := b.getRefreshCredToken(
		ctx,
		req.Storage,
		persistence.AuthCodeName(data.Get("name").(string)),
		expiryDelta,
	)
	switch {
	case err == ErrNotConfigured:
		return logical.ErrorResponse("not configured"), nil
	case err != nil:
		return nil, err
	case entry == nil:
		return nil, nil
	case !entry.TokenIssued():
		if entry.UserError != "" {
			return logical.ErrorResponse(entry.UserError), nil
		}

		return logical.ErrorResponse("token pending issuance"), nil
	case !b.tokenValid(entry.Token, expiryDelta):
		if entry.UserError != "" {
			return logical.ErrorResponse(entry.UserError), nil
		}

		return logical.ErrorResponse("token expired"), nil
	}

	rd := map[string]interface{}{
		"access_token": entry.AccessToken,
		"type":         entry.Type(),
	}

	if !entry.Expiry.IsZero() {
		rd["expire_time"] = entry.Expiry
	}

	if len(entry.ExtraData) > 0 {
		rd["extra_data"] = entry.ExtraData
	}

	resp := &logical.Response{
		Data: rd,
	}
	if entry.UserError != "" {
		resp.Warnings = []string{
			fmt.Sprintf("token will expire: %s", entry.UserError),
		}
	} else if entry.TransientErrorsSinceLastIssue > 0 {
		resp.Warnings = []string{
			fmt.Sprintf(
				"%d attempt(s) to refresh this token failed, most recently: %s",
				entry.TransientErrorsSinceLastIssue,
				entry.LastTransientError,
			),
		}
	}
	return resp, nil
}

func (b *backend) credsUpdateAuthorizationCodeOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	} else if c.Config.ClientSecret == "" {
		return logical.ErrorResponse("missing client secret in configuration"), nil
	}

	ops := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret)

	code, ok := data.GetOk("code")
	if !ok {
		return logical.ErrorResponse("missing code"), nil
	}
	if _, ok := data.GetOk("refresh_token"); ok {
		return logical.ErrorResponse("cannot use refresh_token with authorization_code grant type"), nil
	}

	tok, err := ops.AuthCodeExchange(
		ctx,
		code.(string),
		provider.WithRedirectURL(data.Get("redirect_url").(string)),
		provider.WithProviderOptions(data.Get("provider_options").(map[string]string)),
	)
	if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "exchange failed").Error()), nil
	} else if err != nil {
		return nil, err
	}

	entry := &persistence.AuthCodeEntry{}
	entry.SetToken(tok)

	if err := b.data.Managers(req.Storage).AuthCode().WriteAuthCodeEntry(ctx, persistence.AuthCodeName(data.Get("name").(string)), entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) credsUpdateRefreshTokenOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	ops := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret)

	refreshToken, ok := data.GetOk("refresh_token")
	if !ok {
		return logical.ErrorResponse("missing refresh_token"), nil
	}
	if _, ok := data.GetOk("code"); ok {
		return logical.ErrorResponse("cannot use code with refresh_token grant type"), nil
	}

	tok := &provider.Token{
		Token: &oauth2.Token{
			RefreshToken: refreshToken.(string),
		},
	}
	tok, err = ops.RefreshToken(
		ctx,
		tok,
		provider.WithProviderOptions(data.Get("provider_options").(map[string]string)),
	)
	if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "refresh failed").Error()), nil
	} else if err != nil {
		return nil, err
	}

	entry := &persistence.AuthCodeEntry{}
	entry.SetToken(tok)

	if err := b.data.Managers(req.Storage).AuthCode().WriteAuthCodeEntry(ctx, persistence.AuthCodeName(data.Get("name").(string)), entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) credsUpdateDeviceCodeOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	ops := c.Provider.Public(c.Config.ClientID)

	// If a device code isn't provided, we'll end up setting this response to
	// information important to return to the user. Otherwise, it will remain
	// nil.
	var resp *logical.Response

	// The spec provides for a default polling interval of 5 seconds, so we'll
	// start there.
	interval := 5 * time.Second

	deviceCode, ok := data.GetOk("device_code")
	if !ok {
		now := b.clock.Now()

		auth, ok, err := ops.DeviceCodeAuth(
			ctx,
			provider.WithScopes(data.Get("scopes").([]string)),
			provider.WithProviderOptions(data.Get("provider_options").(map[string]string)),
		)
		if errmark.MarkedUser(err) {
			return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "device code authorization request failed").Error()), nil
		} else if err != nil {
			return nil, err
		} else if !ok {
			return logical.ErrorResponse("device code URL not available"), nil
		}

		if auth.Interval > 0 {
			interval = time.Duration(auth.Interval) * time.Second
		}

		// Now we have a device code, so we can continue with the request.
		deviceCode = auth.DeviceCode

		// We're going to return a response with the information the user
		// needs to process the device code flow.
		resp = &logical.Response{
			Data: map[string]interface{}{
				"user_code":        auth.UserCode,
				"verification_uri": auth.VerificationURI,
				"expire_time":      now.Add(time.Duration(auth.ExpiresIn) * time.Second),
			},
		}
		if auth.VerificationURIComplete != "" {
			resp.Data["verification_uri_complete"] = auth.VerificationURIComplete
		}
	}

	dae := &persistence.DeviceAuthEntry{
		DeviceCode:      deviceCode.(string),
		Interval:        int32(interval.Round(time.Second) / time.Second),
		ProviderOptions: data.Get("provider_options").(map[string]string),
	}
	ace := &persistence.AuthCodeEntry{}

	// If we get this far, we're guaranteed to have a device code. We'll do
	// one request to make sure that it's not completely broken. Then we'll
	// submit it to be polled.
	dae, ace, err = deviceAuthExchange(ctx, ops, dae, ace)
	if err != nil {
		return nil, err
	} else if ace.UserError != "" {
		return logical.ErrorResponse(ace.UserError), nil
	}

	err = b.data.Managers(req.Storage).AuthCode().WithLock(persistence.AuthCodeName(data.Get("name").(string)), func(acm *persistence.LockedAuthCodeManager) error {
		if !ace.TokenIssued() {
			// We'll write the device auth out first. In the issuer, it checks
			// that the target entry exists first (because someone could delete
			// it before the exchange succeeds, anyway).
			//
			// Locks on the devices/ prefix are held by the corresponding
			// credential lock, so we don't have to do any extra work to write
			// this out here.
			if err := acm.WriteDeviceAuthEntry(ctx, dae); err != nil {
				return err
			}
		}

		if err := acm.WriteAuthCodeEntry(ctx, ace); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (b *backend) credsUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	hnd, found := credUpdateGrantHandlers[credGrantType(data)]
	if !found {
		return logical.ErrorResponse("unknown grant_type"), nil
	}

	return hnd(b)(ctx, req, data)
}

func (b *backend) credsDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.data.Managers(req.Storage).AuthCode().DeleteAuthCodeEntry(ctx, persistence.AuthCodeName(data.Get("name").(string))); err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	CredsPathPrefix = "creds/"
)

var credsFields = map[string]*framework.FieldSchema{
	// fields for both read & write operations
	"name": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the credential.",
	},
	// fields for read operation
	"minimum_seconds": {
		Type:        framework.TypeInt,
		Description: "Minimum remaining seconds to allow when reusing access token.",
		Default:     0,
		Query:       true,
	},
	// fields for write operation
	"grant_type": {
		Type:          framework.TypeString,
		Description:   "The grant type to use for this operation.",
		AllowedValues: credGrantTypes(),
	},
	"code": {
		Type:        framework.TypeString,
		Description: "Specifies the response code to exchange for a full token.",
	},
	"redirect_url": {
		Type:        framework.TypeString,
		Description: "Specifies the redirect URL to provide when exchanging (required by some services and must be equivalent to the redirect URL provided to the authorization code URL).",
	},
	"refresh_token": {
		Type:        framework.TypeString,
		Description: "Specifies a refresh token retrieved from the provider by some means external to this plugin.",
	},
	"device_code": {
		Type:        framework.TypeString,
		Description: "Specifies a device token retrieved from the provider by some means external to this plugin.",
	},
	"scopes": {
		Type:        framework.TypeStringSlice,
		Description: "Specifies the scopes to provide for a device code authorization request.",
	},
	"provider_options": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies a list of options to pass on to the provider for configuring this token exchange.",
	},
}

const credsHelpSynopsis = `
Provides access tokens for authorized credentials.
`

const credsHelpDescription = `
This endpoint allows users to configure credentials to the service.
Write a credential to this endpoint by specifying the code from the
HTTP response of the authorization redirect. If the code is valid,
the access token will be available when reading the endpoint.
`

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: CredsPathPrefix + nameRegex("name", "/") + `$`,
		Fields:  credsFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.credsReadOperation,
				Summary:  "Get a current access token for this credential.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.credsUpdateOperation,
				Summary:  "Write a new credential or update an existing credential.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.credsDeleteOperation,
				Summary:  "Remove a credential.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(credsHelpSynopsis),
		HelpDescription: strings.TrimSpace(credsHelpDescription),
	}
}
