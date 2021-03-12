package backend

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"golang.org/x/oauth2"
)

const (
	selfPath       = "self"
	selfPathPrefix = selfPath + "/"
)

// selfKey hashes the name and splits the first few bytes into separate buckets
// for performance reasons.
func selfKey(name string) string {
	hash := sha256.Sum224([]byte(name))
	first, second, rest := hash[:2], hash[2:4], hash[4:]
	return selfPathPrefix + fmt.Sprintf("%x/%x/%x", first, second, rest)
}

func (b *backend) selfReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key := selfKey(data.Get("name").(string))

	tok, err := b.getUpdateClientCredsToken(ctx, req.Storage, key, data)
	switch {
	case errors.Is(err, ErrNotConfigured):
		return logical.ErrorResponse("not configured"), nil
	case errmark.Matches(err, errmark.RuleType(&oauth2.RetrieveError{})) || errmark.MarkedUser(err):
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "client credentials flow failed").Error()), nil
	case err != nil:
		return nil, err
	case tok == nil:
		return nil, nil
	case !tokenValid(tok, data):
		return logical.ErrorResponse("token expired"), nil
	}

	rd := map[string]interface{}{
		"access_token": tok.AccessToken,
		"type":         tok.Type(),
	}

	if !tok.Expiry.IsZero() {
		rd["expire_time"] = tok.Expiry
	}

	if len(tok.ExtraData) > 0 {
		rd["extra_data"] = tok.ExtraData
	}

	resp := &logical.Response{
		Data: rd,
	}
	return resp, nil
}

func (b *backend) selfDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key := selfKey(data.Get("name").(string))

	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	if err := req.Storage.Delete(ctx, key); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) selfConfigReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key := selfKey(data.Get("name").(string))

	cc, err := b.getSelfToken(ctx, req.Storage, key)
	if err != nil {
		return nil, err
	} else if cc == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"token_url_prams": cc.Config.TokenURLParams,
			"scopes":          cc.Config.Scopes,
		},
	}
	return resp, nil
}

func (b *backend) selfConfigUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key := selfKey(data.Get("name").(string))

	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	cc := &selfToken{}
	cc.Config.TokenURLParams = data.Get("token_url_params").(map[string]string)
	cc.Config.Scopes = data.Get("scopes").([]string)

	tok, err := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret).ClientCredentials(
		ctx,
		provider.WithURLParams(cc.Config.TokenURLParams),
		provider.WithScopes(cc.Config.Scopes),
	)
	if errmark.Matches(err, errmark.RuleType(&oauth2.RetrieveError{})) || errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "client credentials flow failed").Error()), nil
	} else if err != nil {
		return nil, err
	}

	cc.Token = tok

	entry, err := logical.StorageEntryJSON(key, cc)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

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
		Pattern: selfPathPrefix + nameRegex("name") + `$`,
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

var selfConfigFields = map[string]*framework.FieldSchema{
	// fields for both read & write operations
	"name": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the credential.",
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

const selfConfigHelpSynopsis = `
Configures individual client credentials.
`

const selfConfigHelpDescription = `
This endpoint configures the scopes and additional URL parameters for
the token endpoint of a client credentials flow.
`

func pathSelfConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: selfPathPrefix + nameRegex("name") + `/config$`,
		Fields:  selfConfigFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.selfConfigReadOperation,
				Summary:  "Return the current configuration for this credential.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.selfConfigUpdateOperation,
				Summary:  "Create a new credential configuration or replace the configuration with new settings.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(selfConfigHelpSynopsis),
		HelpDescription: strings.TrimSpace(selfConfigHelpDescription),
	}
}
