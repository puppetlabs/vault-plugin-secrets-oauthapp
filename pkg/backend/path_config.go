package backend

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

func (b *backend) configReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id":        c.Config.ClientID,
			"auth_url_params":  c.Config.AuthURLParams,
			"provider":         c.Config.ProviderName,
			"provider_version": c.Config.ProviderVersion,
			"provider_options": c.Config.ProviderOptions,
		},
	}
	return resp, nil
}

func (b *backend) configUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientID, ok := data.GetOk("client_id")
	if !ok {
		return logical.ErrorResponse("missing client ID"), nil
	}

	providerName, ok := data.GetOk("provider")
	if !ok {
		return logical.ErrorResponse("missing provider"), nil
	}

	providerOptions := data.Get("provider_options").(map[string]string)

	p, err := b.providerRegistry.New(ctx, providerName.(string), providerOptions)
	if errors.Is(err, provider.ErrNoSuchProvider) {
		return logical.ErrorResponse("provider %q does not exist", providerName), nil
	} else if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmark.MarkShort(err).Error()), nil
	} else if err != nil {
		return nil, err
	}

	c := &persistence.ConfigEntry{
		ClientID:        clientID.(string),
		ClientSecret:    data.Get("client_secret").(string),
		AuthURLParams:   data.Get("auth_url_params").(map[string]string),
		ProviderName:    providerName.(string),
		ProviderVersion: p.Version(),
		ProviderOptions: providerOptions,
	}
	if err := b.data.Managers(req.Storage).Config().WriteConfig(ctx, c); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *backend) configDeleteOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := b.data.Managers(req.Storage).Config().DeleteConfig(ctx); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *backend) configAuthCodeURLUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	state, ok := data.GetOk("state")
	if !ok {
		return logical.ErrorResponse("missing state"), nil
	}

	url, ok := c.Provider.Public(c.Config.ClientID).AuthCodeURL(
		state.(string),
		provider.WithRedirectURL(data.Get("redirect_url").(string)),
		provider.WithScopes(data.Get("scopes").([]string)),
		provider.WithURLParams(data.Get("auth_url_params").(map[string]string)),
		provider.WithURLParams(c.Config.AuthURLParams),
	)
	if !ok {
		return logical.ErrorResponse("authorization code URL not available"), nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"url": url,
		},
	}
	return resp, nil
}

const (
	ConfigPath            = "config"
	ConfigPathPrefix      = ConfigPath + "/"
	ConfigAuthCodeURLPath = ConfigPathPrefix + "auth_code_url"
)

var configFields = map[string]*framework.FieldSchema{
	"client_id": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 client ID.",
	},
	"client_secret": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 client secret.",
	},
	"auth_url_params": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies the additional query parameters to add to the authorization code URL.",
	},
	"provider": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 provider.",
	},
	"provider_options": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies any provider-specific options.",
	},
}

const configHelpSynopsis = `
Configures OAuth 2.0 client information.
`

const configHelpDescription = `
This endpoint configures the endpoint, client ID, and secret for
authorization code exchange. The endpoint is selected by the given
provider. Additionally, you may specify URL parameters to add to the
authorization code endpoint.
`

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ConfigPath + `$`,
		Fields:  configFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.configReadOperation,
				Summary:  "Return the current configuration for this mount.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.configUpdateOperation,
				Summary:  "Create a new client configuration or replace the configuration with new client information.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.configDeleteOperation,
				Summary:  "Delete the client configuration, invalidating all credentials.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(configHelpSynopsis),
		HelpDescription: strings.TrimSpace(configHelpDescription),
	}
}

var configAuthCodeURLFields = map[string]*framework.FieldSchema{
	"auth_url_params": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies the additional query parameters to add to the authorization code URL.",
	},
	"redirect_url": {
		Type:        framework.TypeString,
		Description: "The URL to redirect to after the authorization flow completes.",
	},
	"scopes": {
		Type:        framework.TypeCommaStringSlice,
		Description: "The scopes to request for authorization.",
	},
	"state": {
		Type:        framework.TypeString,
		Description: "Specifies the state to set in the authorization code URL.",
	},
}

const configAuthCodeURLHelpSynopsis = `
Generates authorization code URLs for the current configuration.
`

const configAuthCodeURLHelpDescription = `
This endpoint merges the configuration data with requested parameters
like a redirect URL and scopes to create an authorization code URL.
The code returned in the response should be written to a credential
endpoint to start managing authentication tokens.
`

func pathConfigAuthCodeURL(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ConfigAuthCodeURLPath + `$`,
		Fields:  configAuthCodeURLFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.configAuthCodeURLUpdateOperation,
				Summary:  "Generate an initial authorization code URL.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(configAuthCodeURLHelpSynopsis),
		HelpDescription: strings.TrimSpace(configAuthCodeURLHelpDescription),
	}
}
