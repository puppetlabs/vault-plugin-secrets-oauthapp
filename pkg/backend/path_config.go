package backend

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"golang.org/x/oauth2"
)

type config struct {
	ClientID        string            `json:"client_id"`
	ClientSecret    string            `json:"client_secret"`
	AuthURLParams   map[string]string `json:"auth_url_params"`
	ProviderName    string            `json:"provider_name"`
	ProviderVersion int               `json:"provider_version"`
	ProviderOptions map[string]string `json:"provider_options"`
}

func (c *config) provider() (provider.Provider, error) {
	return provider.NewAt(c.ProviderName, c.ProviderVersion, c.ProviderOptions)
}

func getConfig(ctx context.Context, storage logical.Storage) (*config, error) {
	entry, err := storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	c := &config{}
	if err := entry.DecodeJSON(c); err != nil {
		return nil, err
	}

	return c, nil
}

func (b *backend) configReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id":        c.ClientID,
			"auth_url_params":  c.AuthURLParams,
			"provider_name":    c.ProviderName,
			"provider_version": c.ProviderVersion,
			"provider_options": c.ProviderOptions,
		},
	}
	return resp, nil
}

func (b *backend) configUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientID, ok := data.GetOk("client_id")
	if !ok {
		return logical.ErrorResponse("missing client ID"), nil
	}

	clientSecret, ok := data.GetOk("client_secret")
	if !ok {
		return logical.ErrorResponse("missing client secret"), nil
	}

	providerName, ok := data.GetOk("provider")
	if !ok {
		return logical.ErrorResponse("missing provider"), nil
	}

	providerOptions := data.Get("provider_options").(map[string]string)

	p, err := provider.New(providerName.(string), providerOptions)
	if err == provider.ErrNoSuchProvider {
		return logical.ErrorResponse("provider %q does not exist", providerName), nil
	} else if err != nil {
		return nil, err
	}

	c := &config{
		ClientID:        clientID.(string),
		ClientSecret:    clientSecret.(string),
		AuthURLParams:   data.Get("auth_url_params").(map[string]string),
		ProviderName:    providerName.(string),
		ProviderVersion: p.Version(),
		ProviderOptions: providerOptions,
	}

	entry, err := logical.StorageEntryJSON(configPath, c)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) configDeleteOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configPath); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) configAuthCodeURLUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	p, err := c.provider()
	if err != nil {
		return nil, err
	}

	state, ok := data.GetOk("state")
	if !ok {
		return logical.ErrorResponse("missing state"), nil
	}

	cb := p.NewAuthCodeURLConfigBuilder(c.ClientID)

	if redirectURL, ok := data.GetOk("redirect_url"); ok {
		cb = cb.WithRedirectURL(redirectURL.(string))
	}

	if scopes, ok := data.GetOk("scopes"); ok {
		cb = cb.WithScopes(scopes.([]string)...)
	}

	var opts []oauth2.AuthCodeOption
	for k, v := range data.Get("auth_url_params").(map[string]string) {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	for k, v := range c.AuthURLParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}

	url := cb.Build().AuthCodeURL(state.(string), opts...)

	resp := &logical.Response{
		Data: map[string]interface{}{
			"url": url,
		},
	}
	return resp, nil
}

const configPath = "config"

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
Configures the OAuth client information for authorization code exchange.
`

const configHelpDescription = `
This endpoint configures the endpoint, client ID, and secret for
authorization code exchange. The endpoint is selected by the given
provider. Additionally, you may specify URL parameters to add to the
authorization code endpoint.
`

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: configPath + `$`,
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
		Pattern: configPath + `/auth_code_url$`,
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
