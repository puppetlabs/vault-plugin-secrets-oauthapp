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

func (b *backend) serversReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	server, err := b.cache.AuthServer.Get(ctx, req.Storage, persistence.AuthServerName(data.Get("name").(string)))
	if err != nil || server == nil {
		return nil, err
	}
	defer server.Put()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id":        server.ClientID,
			"auth_url_params":  server.AuthURLParams,
			"provider":         server.ProviderName,
			"provider_version": server.ProviderVersion,
			"provider_options": server.ProviderOptions,
		},
	}
	return resp, nil
}

func (b *backend) serversUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	keyer := persistence.AuthServerName(data.Get("name").(string))
	entry := &persistence.AuthServerEntry{
		ClientID:        clientID.(string),
		ClientSecret:    data.Get("client_secret").(string),
		AuthURLParams:   data.Get("auth_url_params").(map[string]string),
		ProviderName:    providerName.(string),
		ProviderVersion: p.Version(),
		ProviderOptions: providerOptions,
	}

	if err := b.data.AuthServer.Manager(req.Storage).WriteAuthServerEntry(ctx, keyer, entry); err != nil {
		return nil, err
	}

	b.cache.AuthServer.Invalidate(keyer)

	return nil, nil
}

func (b *backend) serversDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keyer := persistence.AuthServerName(data.Get("name").(string))

	if err := b.data.AuthServer.Manager(req.Storage).DeleteAuthServerEntry(ctx, keyer); err != nil {
		return nil, err
	}

	b.cache.AuthServer.Invalidate(keyer)

	return nil, nil

}

const (
	ServersPathPrefix = "servers/"
)

var serversFields = map[string]*framework.FieldSchema{
	// fields for both read & write operations
	"name": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the server.",
	},
	// fields for write operation
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

const serversHelpSynopsis = `
Manages the OAuth 2.0 authorization servers used by this plugin.
`

const serversHelpDescription = `
This endpoint allows users to configure the set of authorization
servers and client information for use in other endpoints. Other
endpoints that contain a server name as a path parameter or field
reference the names of servers defined in this endpoint.
`

func pathServers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ServersPathPrefix + nameRegex("name") + `$`,
		Fields:  serversFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.serversReadOperation,
				Summary:  "Get information about an OAuth 2.0 authorization server.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.serversUpdateOperation,
				Summary:  "Write information about an OAuth 2.0 authorization server.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.serversDeleteOperation,
				Summary:  "Remove an OAuth 2.0 authorization server.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(serversHelpSynopsis),
		HelpDescription: strings.TrimSpace(serversHelpDescription),
	}
}
