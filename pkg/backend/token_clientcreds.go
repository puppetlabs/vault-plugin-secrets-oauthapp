package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

func (b *backend) updateClientCredsToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*provider.Token, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	// In case someone else updated this token from under us, we'll re-request
	// it here with the lock acquired.
	cc, err := getSelfTokenLocked(ctx, storage, key)
	switch {
	case err != nil:
		return nil, err
	case cc == nil:
		cc = &selfToken{}
	case tokenValid(cc.Token, data):
		return cc.Token, nil
	}

	c, err := b.getCache(ctx, storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return nil, ErrNotConfigured
	}

	updated, err := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret).ClientCredentials(
		ctx,
		provider.WithURLParams(cc.Config.TokenURLParams),
		provider.WithScopes(cc.Config.Scopes),
	)
	if err != nil {
		return nil, err
	}

	// Store the new creds.
	cc.Token = updated

	entry, err := logical.StorageEntryJSON(key, cc)
	if err != nil {
		return nil, err
	}

	if err := storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return cc.Token, nil
}

func (b *backend) getUpdateClientCredsToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*provider.Token, error) {
	cc, err := b.getSelfToken(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if cc == nil {
		cc = &selfToken{}
	}

	if !tokenValid(cc.Token, data) {
		return b.updateClientCredsToken(ctx, storage, key, data)
	}

	return cc.Token, nil
}
