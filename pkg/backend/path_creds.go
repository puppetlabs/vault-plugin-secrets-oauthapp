// TODO: We should upgrade credential keys to use a cryptographically secure
// hash algorithm.
/* #nosec G401 G505 */

package backend

import (
	"context"
	"crypto/sha1"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"golang.org/x/oauth2"
)

const (
	credsPath       = "creds"
	credsPathPrefix = credsPath + "/"
)

// credKey hashes the name and splits the first few bytes into separate buckets
// for performance reasons.
func credKey(name string) string {
	hash := sha1.Sum([]byte(name))
	first, second, rest := hash[:2], hash[2:4], hash[4:]
	return credsPathPrefix + fmt.Sprintf("%x/%x/%x", first, second, rest)
}

func (b *backend) credsReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key := credKey(data.Get("name").(string))

	tok, err := b.getRefreshToken(ctx, req.Storage, key, data)
	switch {
	case err == ErrNotConfigured:
		return logical.ErrorResponse("not configured"), nil
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

func (b *backend) credsUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c, err := b.getCache(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	key := credKey(data.Get("name").(string))

	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	var tok *provider.Token

	cb := c.Provider.NewExchangeConfigBuilder(c.Config.ClientID, c.Config.ClientSecret)

	for name, value := range data.Get("provider_options").(map[string]string) {
		cb = cb.WithOption(name, value)
	}

	if code, ok := data.GetOk("code"); ok {
		if _, ok := data.GetOk("refresh_token"); ok {
			return logical.ErrorResponse("cannot use both code and refresh_token"), nil
		}

		if redirectURL, ok := data.GetOk("redirect_url"); ok {
			cb = cb.WithRedirectURL(redirectURL.(string))
		}

		tok, err = cb.Build().Exchange(ctx, code.(string))
		if rErr, ok := err.(*oauth2.RetrieveError); ok {
			b.logger.Error("invalid code", "error", rErr)
			return logical.ErrorResponse("invalid code"), nil
		} else if err != nil {
			return nil, err
		}
	} else if refreshToken, ok := data.GetOk("refresh_token"); ok {
		tok = &provider.Token{
			Token: &oauth2.Token{
				RefreshToken: refreshToken.(string),
			},
		}
		tok, err = cb.Build().Refresh(ctx, tok)
		if rErr, ok := err.(*oauth2.RetrieveError); ok {
			b.logger.Error("invalid refresh_token", "error", rErr)
			return logical.ErrorResponse("invalid refresh_token"), nil
		} else if err != nil {
			return nil, err
		}
		// tok now contains a refresh token and an access token
	} else {
		return logical.ErrorResponse("missing code or refresh_token"), nil
	}

	entry, err := logical.StorageEntryJSON(key, tok)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) credsDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	key := credKey(data.Get("name").(string))

	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	if err := req.Storage.Delete(ctx, key); err != nil {
		return nil, err
	}

	return nil, nil
}

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
	},
	// fields for write operation
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
	"provider_options": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies a list of options to pass on to the provider for configuring this token exchange.",
	},
}

// Allow characters not special to urls or shells
// Derived from framework.GenericNameWithAtRegex
func credentialNameRegex(name string) string {
	return fmt.Sprintf(`(?P<%s>\w(([\w.@~!_,:^-]+)?\w)?)`, name)
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
		Pattern: credsPathPrefix + credentialNameRegex("name") + `$`,
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
