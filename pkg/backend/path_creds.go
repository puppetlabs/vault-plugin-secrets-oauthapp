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
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"golang.org/x/oauth2"
)

const (
	credsPath       = "creds"
	credsPathPrefix = credsPath + "/"
)

const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
	grantTypeDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
)

var (
	schemaAllowedGrantTypeValues = []interface{}{
		grantTypeAuthorizationCode,
		grantTypeRefreshToken,
		grantTypeDeviceCode,
	}
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

	tok, err := b.getRefreshAuthCodeToken(ctx, req.Storage, key, data)
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

	ops := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret)

	// Figure out which mode we want to operate in: authorization code
	// (default), refresh token, or device code.
	grantType, ok := data.GetOk("grant_type")
	if !ok {
		if _, ok := data.GetOk("refresh_token"); ok {
			grantType = grantTypeRefreshToken
		} else {
			grantType = grantTypeAuthorizationCode
		}
	}

	var tok *provider.Token
	switch grantType {
	case grantTypeAuthorizationCode:
		code, ok := data.GetOk("code")
		if !ok {
			return logical.ErrorResponse("missing code"), nil
		}
		if _, ok := data.GetOk("refresh_token"); ok {
			return logical.ErrorResponse("cannot use refresh_token with authorization_code grant type"), nil
		}

		tok, err = ops.AuthCodeExchange(
			ctx,
			code.(string),
			provider.WithRedirectURL(data.Get("redirect_url").(string)),
			provider.WithProviderOptions(data.Get("provider_options").(map[string]string)),
		)
		if errmark.Matches(err, errmark.RuleType(&oauth2.RetrieveError{})) || errmark.MarkedUser(err) {
			return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "exchange failed").Error()), nil
		} else if err != nil {
			return nil, err
		}
	case grantTypeRefreshToken:
		refreshToken, ok := data.GetOk("refresh_token")
		if !ok {
			return logical.ErrorResponse("missing refresh_token"), nil
		}
		if _, ok := data.GetOk("code"); ok {
			return logical.ErrorResponse("cannot use code with refresh_token grant type"), nil
		}

		tok = &provider.Token{
			Token: &oauth2.Token{
				RefreshToken: refreshToken.(string),
			},
		}
		tok, err = ops.RefreshToken(
			ctx,
			tok,
			provider.WithProviderOptions(data.Get("provider_options").(map[string]string)),
		)
		if errmark.Matches(err, errmark.RuleType(&oauth2.RetrieveError{})) || errmark.MarkedUser(err) {
			return logical.ErrorResponse(errmap.Wrap(errmark.MarkShort(err), "refresh failed").Error()), nil
		} else if err != nil {
			return nil, err
		}
	case grantTypeDeviceCode:
		// TODO: Response will contain:
		//
		// {
		//   "user_code": "BDWD-HQPK",
		//   "verification_uri": "https://example.okta.com/device",
		//   "verification_uri_complete": "https://example.okta.com/device?user_code=BDWD-HQPK",
		//   "expire_time": "2021-03-10T23:00:00Z"
		// }
	default:
		return logical.ErrorResponse("unknown grant_type"), nil
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
		Query:       true,
	},
	// fields for write operation
	"grant_type": {
		Type:          framework.TypeString,
		Description:   "The grant type to use for this operation.",
		AllowedValues: schemaAllowedGrantTypeValues,
	},
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
		Pattern: credsPathPrefix + nameRegex("name") + `$`,
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
