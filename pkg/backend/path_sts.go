package backend

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
)

func (b *backend) stsReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRefreshCredToken(
		ctx,
		req.Storage,
		persistence.AuthCodeName(data.Get("name").(string)),
		defaultExpiryDelta,
	)
	switch {
	case err != nil:
		return nil, errmark.MarkShort(err)
	case entry == nil:
		return nil, nil
	case !entry.TokenIssued():
		if entry.AuthServerError != "" {
			return logical.ErrorResponse("server %q has configuration problems: %s", entry.AuthServerName, entry.AuthServerError), nil
		} else if entry.UserError != "" {
			return logical.ErrorResponse(entry.UserError), nil
		}

		return logical.ErrorResponse("token pending issuance"), nil
	case !b.tokenValid(entry.Token, defaultExpiryDelta):
		if entry.AuthServerError != "" {
			return logical.ErrorResponse("server %q has configuration problems: %s", entry.AuthServerName, entry.AuthServerError), nil
		} else if entry.UserError != "" {
			return logical.ErrorResponse(entry.UserError), nil
		}

		return logical.ErrorResponse("token expired"), nil
	}

	ops, put, err := b.getProviderOperations(ctx, req.Storage, persistence.AuthServerName(entry.AuthServerName), defaultExpiryDelta)
	if errmark.MarkedUser(err) {
		return logical.ErrorResponse(fmt.Errorf("server %q has configuration problems: %w", entry.AuthServerName, errmark.MarkShort(err)).Error()), nil
	} else if err != nil {
		return nil, err
	}
	defer put()

	tok, err := ops.TokenExchange(
		ctx,
		entry.Token,
		provider.WithScopes(data.Get("scopes").([]string)),
		provider.WithAudiences(data.Get("audiences").([]string)),
		provider.WithResources(data.Get("resources").([]string)),
		provider.WithProviderOptions(entry.ProviderOptions),
	)
	if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "exchange failed").Error()), nil
	} else if err != nil {
		return nil, err
	}

	rd := map[string]interface{}{
		"access_token": tok.AccessToken,
		"type":         tok.Type(),
	}

	if !tok.Expiry.IsZero() {
		rd["expire_time"] = tok.Expiry
	}

	return &logical.Response{Data: rd}, nil
}

const (
	STSPathPrefix = "sts/"
)

var stsFields = map[string]*framework.FieldSchema{
	// fields for both read & write operations
	"name": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the credential.",
	},
	// fields for read operation
	"scopes": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Specifies the subset of scopes to request from the authorization server.",
		Query:       true,
	},
	"audiences": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Specifies the target audiences for the minted token.",
		Query:       true,
	},
	"resources": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Specifies the target RFC 8707 resource indicators for the minted token.",
		Query:       true,
	},
}

const stsHelpSynopsis = `
Performs RFC 8693 token exchange for an existing credential.
`

const stsHelpDescription = `
This endpoint performs a token exchange for an already stored OAuth
2.0 credential. Reading from a corresponding credential path under
this endpoint performs the exchange with a requested
urn:ietf:params:oauth:token-type:access_token token type and returns
the resulting token in the response.
`

func pathSTS(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: STSPathPrefix + nameRegex("name") + `$`,
		Fields:  stsFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.stsReadOperation,
				Summary:  "Perform a token exchange for an existing credential.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(stsHelpSynopsis),
		HelpDescription: strings.TrimSpace(stsHelpDescription),
	}
}
