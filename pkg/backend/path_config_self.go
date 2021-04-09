package backend

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
	"golang.org/x/oauth2"
)

func (b *backend) configSelfReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := b.data.Managers(req.Storage).ClientCreds().ReadClientCredsEntry(ctx, persistence.ClientCredsName(data.Get("name").(string)))
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"token_url_params": entry.Config.TokenURLParams,
			"scopes":           entry.Config.Scopes,
		},
	}
	return resp, nil
}

func (b *backend) configSelfUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	entry := &persistence.ClientCredsEntry{}
	entry.Config.TokenURLParams = data.Get("token_url_params").(map[string]string)
	entry.Config.Scopes = data.Get("scopes").([]string)

	tok, err := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret).ClientCredentials(
		ctx,
		provider.WithURLParams(entry.Config.TokenURLParams),
		provider.WithScopes(entry.Config.Scopes),
	)
	if errmark.Matches(err, errmark.RuleType(&oauth2.RetrieveError{})) || errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "client credentials flow failed").Error()), nil
	} else if err != nil {
		return nil, err
	}

	entry.Token = tok

	if err := b.data.Managers(req.Storage).ClientCreds().WriteClientCredsEntry(ctx, persistence.ClientCredsName(data.Get("name").(string)), entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) configSelfDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.data.Managers(req.Storage).ClientCreds().DeleteClientCredsEntry(ctx, persistence.ClientCredsName(data.Get("name").(string))); err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	ConfigSelfPathPrefix = ConfigPathPrefix + "self/"
)

var configSelfFields = map[string]*framework.FieldSchema{
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
	"token_url_params": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies the additional query parameters to add to the token URL.",
	},
	"scopes": {
		Type:        framework.TypeCommaStringSlice,
		Description: "The scopes to request for authorization.",
	},
}

const configSelfHelpSynopsis = `
Configures individual client credentials.
`

const configSelfHelpDescription = `
This endpoint configures the scopes and additional URL parameters for
the token endpoint of a client credentials flow.
`

func pathConfigSelf(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ConfigSelfPathPrefix + nameRegex("name") + `$`,
		Fields:  configSelfFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.configSelfReadOperation,
				Summary:  "Return the current configuration for this credential.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.configSelfUpdateOperation,
				Summary:  "Create a new credential configuration or replace the configuration with new settings.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.configSelfDeleteOperation,
				Summary:  "Remove a credential configuration and any associated token.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(configSelfHelpSynopsis),
		HelpDescription: strings.TrimSpace(configSelfHelpDescription),
	}
}
