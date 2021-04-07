package backend

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
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
	case errors.Is(err, ErrNotConfigured):
		return logical.ErrorResponse("not configured"), nil
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
		"access_token": entry.Token.AccessToken,
		"type":         entry.Token.Type(),
	}

	if !entry.Token.Expiry.IsZero() {
		rd["expire_time"] = entry.Token.Expiry
	}

	if len(entry.Token.ExtraData) > 0 {
		rd["extra_data"] = entry.Token.ExtraData
	}

	resp := &logical.Response{
		Data: rd,
	}
	return resp, nil
}

func (b *backend) selfDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := b.data.Managers(req.Storage).ClientCreds().WithLock(persistence.ClientCredsName(data.Get("name").(string)), func(cm *persistence.LockedClientCredsManager) error {
		entry, err := cm.ReadClientCredsEntry(ctx)
		if err != nil || entry == nil || entry.Token == nil {
			return nil
		}

		entry.Token = nil
		return cm.WriteClientCredsEntry(ctx, entry)
	})
	return nil, err
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
}

const selfHelpSynopsis = `
Provides access tokens for this application using the OAuth 2.0 client credentials flow.
`

const selfHelpDescription = `
This endpoint allows you to read and delete OAuth 2.0 access tokens
using the client credentials flow. Reads from a given path are cached
until expiration and will be automatically resubmitted to the IdP as
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
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.selfDeleteOperation,
				Summary:  "Remove a credential.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(selfHelpSynopsis),
		HelpDescription: strings.TrimSpace(selfHelpDescription),
	}
}
