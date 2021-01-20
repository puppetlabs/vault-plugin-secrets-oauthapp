package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

type clientCreds struct {
	Config struct {
		Scopes         []string          `json:"scopes"`
		TokenURLParams map[string]string `json:"token_url_params"`
	} `json:"config"`
	Token *provider.Token `json:"token"`
}

func getClientCredsLocked(ctx context.Context, storage logical.Storage, key string) (*clientCreds, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	cc := &clientCreds{}
	if err := entry.DecodeJSON(cc); err != nil {
		return nil, err
	}

	return cc, nil
}

func (b *backend) getClientCreds(ctx context.Context, storage logical.Storage, key string) (*clientCreds, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.RLock()
	defer lock.RUnlock()

	cc, err := getClientCredsLocked(ctx, storage, key)
	if err != nil {
		return nil, err
	}

	return cc, nil
}

func (b *backend) updateClientCredsToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*provider.Token, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	// In case someone else updated this token from under us, we'll re-request
	// it here with the lock acquired.
	cc, err := getClientCredsLocked(ctx, storage, key)
	switch {
	case err != nil:
		return nil, err
	case cc == nil:
		cc = &clientCreds{}
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
	cc, err := b.getClientCreds(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if cc == nil {
		cc = &clientCreds{}
	}

	if !tokenValid(cc.Token, data) {
		return b.updateClientCredsToken(ctx, storage, key, data)
	}

	return cc.Token, nil
}
