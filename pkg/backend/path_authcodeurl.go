package backend

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

func (b *backend) authCodeURLUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ops, put, err := b.getProviderOperations(ctx, req.Storage, persistence.AuthServerName(data.Get("server").(string)), defaultExpiryDelta)
	if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmark.MarkShort(err).Error()), nil
	} else if err != nil {
		return nil, err
	}
	defer put()

	resp := &logical.Response{
		Data: make(map[string]interface{}),
	}

	state, ok := data.GetOk("state")
	if !ok {
		rd := make([]byte, 32)
		if _, err := b.GetRandomReader().Read(rd); err != nil {
			return nil, err
		}

		state = base64.RawURLEncoding.EncodeToString(rd)
		resp.Data["state"] = state
	}

	url, ok := ops.Public().AuthCodeURL(
		state.(string),
		provider.WithRedirectURL(data.Get("redirect_url").(string)),
		provider.WithScopes(data.Get("scopes").([]string)),
		provider.WithURLParams(data.Get("auth_url_params").(map[string]string)),
		provider.WithProviderOptions(data.Get("provider_options").(map[string]string)),
	)
	if !ok {
		return logical.ErrorResponse("authorization code URL not available"), nil
	}

	resp.Data["url"] = url

	return resp, nil
}

const (
	AuthCodeURLPath = "auth-code-url"
)

var authCodeURLFields = map[string]*framework.FieldSchema{
	// fields for write operations
	"server": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the server.",
	},
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
	"provider_options": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies any provider-specific options.",
	},
}

const authCodeURLHelpSynopsis = `
Generates authorization code URLs for a server configuration.
`

const authCodeURLHelpDescription = `
This endpoint merges server configuration data with requested
parameters like a redirect URL and scopes to create an authorization
code URL. The code returned in the response should be written to a
credential endpoint to start managing authentication tokens.
`

func pathAuthCodeURL(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: AuthCodeURLPath + `$`,
		Fields:  authCodeURLFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.authCodeURLUpdateOperation,
				Summary:  "Get an initial authorization code URL.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(authCodeURLHelpSynopsis),
		HelpDescription: strings.TrimSpace(authCodeURLHelpDescription),
	}
}
