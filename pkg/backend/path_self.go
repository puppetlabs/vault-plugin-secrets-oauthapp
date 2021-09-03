package backend

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"golang.org/x/oauth2"
)

func (b *backend) selfReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	expiryDelta := time.Duration(data.Get("minimum_seconds").(int)) * time.Second

	entry, err := b.getUpdateClientCredsToken(
		ctx,
		req.Storage,
		persistence.ClientCredsName(data.Get("name").(string)),
		expiryDelta,
	)
	switch {
	case errmark.Matches(err, errmark.RuleType(&oauth2.RetrieveError{})) || errmark.MarkedUser(err):
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "client credentials flow failed").Error()), nil
	case err != nil:
		return nil, err
	case entry == nil:
		return nil, nil
	case !b.tokenValid(entry.Token, expiryDelta):
		return logical.ErrorResponse("token expired"), nil
	}

	rd := map[string]interface{}{
		"server":       entry.AuthServerName,
		"access_token": entry.Token.AccessToken,
		"type":         entry.Token.Type(),
	}

	if !entry.Token.Expiry.IsZero() {
		rd["expire_time"] = entry.Token.Expiry
	}

	if len(entry.Token.ExtraData) > 0 {
		rd["extra_data"] = entry.Token.ExtraData
	}

	if len(entry.Config.TokenURLParams) > 0 {
		rd["token_url_params"] = entry.Config.TokenURLParams
	}

	if len(entry.Config.Scopes) > 0 {
		rd["scopes"] = entry.Config.Scopes
	}

	if len(entry.Config.ProviderOptions) > 0 {
		rd["provider_options"] = entry.Config.ProviderOptions
	}

	resp := &logical.Response{
		Data: rd,
	}
	return resp, nil
}

func (b *backend) selfUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serverName := data.Get("server").(string)
	ops, put, err := b.getProviderOperations(ctx, req.Storage, serverName, defaultExpiryDelta)
	if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmark.MarkShort(err).Error()), nil
	} else if err != nil {
		return nil, err
	}
	defer put()

	entry := &persistence.ClientCredsEntry{
		AuthServerName: serverName,
	}
	entry.Config.TokenURLParams = data.Get("token_url_params").(map[string]string)
	entry.Config.Scopes = data.Get("scopes").([]string)
	entry.Config.ProviderOptions = data.Get("provider_options").(map[string]string)

	tok, err := ops.Private().ClientCredentials(
		clockctx.WithClock(ctx, b.clock),
		provider.WithURLParams(entry.Config.TokenURLParams),
		provider.WithScopes(entry.Config.Scopes),
		provider.WithProviderOptions(entry.Config.ProviderOptions),
	)
	if errmark.Matches(err, errmark.RuleType(&oauth2.RetrieveError{})) || errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "client credentials flow failed").Error()), nil
	} else if err != nil {
		return nil, err
	}

	entry.Token = tok

	if err := b.data.ClientCreds.Manager(req.Storage).WriteClientCredsEntry(ctx, persistence.ClientCredsName(data.Get("name").(string)), entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) selfDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := b.data.ClientCreds.Manager(req.Storage).DeleteClientCredsEntry(ctx, persistence.ClientCredsName(data.Get("name").(string))); err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	SelfPathPrefix = "self/"
)

var selfFields = map[string]*framework.FieldSchema{
	// fields for both read & write operations
	"name": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the credential.",
	},
	// fields for read operation
	"minimum_seconds": {
		Type:        framework.TypeInt,
		Description: "Minimum remaining seconds to allow when reusing access token.",
		Query:       true,
	},
	// fields for write operation
	"server": {
		Type:        framework.TypeString,
		Description: "The name of the authorization server to use for this credential.",
	},
	"token_url_params": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies the additional query parameters to add to the token URL.",
	},
	"scopes": {
		Type:        framework.TypeCommaStringSlice,
		Description: "The scopes to request for authorization.",
	},
	"provider_options": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies any provider-specific options.",
	},
}

const selfHelpSynopsis = `
Provides access tokens for this application using the OAuth 2.0 client credentials flow.
`

const selfHelpDescription = `
This endpoint allows you to manage OAuth 2.0 access tokens using the
client credentials flow. Reads from a given path are cached until
expiration and will be automatically resubmitted to the IdP as
needed.
`

func pathSelf(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: SelfPathPrefix + nameRegex("name") + `$`,
		Fields:  selfFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.selfReadOperation,
				Summary:  "Get a current access token for this credential.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.selfUpdateOperation,
				Summary:  "Write a new credential or update an existing credential.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.selfDeleteOperation,
				Summary:  "Remove a credential.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(selfHelpSynopsis),
		HelpDescription: strings.TrimSpace(selfHelpDescription),
	}
}
