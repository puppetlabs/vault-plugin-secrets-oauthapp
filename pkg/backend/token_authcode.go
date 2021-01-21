package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

func getAuthCodeTokenLocked(ctx context.Context, storage logical.Storage, key string) (*provider.Token, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	tok := &provider.Token{}
	if err := entry.DecodeJSON(tok); err != nil {
		return nil, err
	}

	return tok, nil
}

func (b *backend) getAuthCodeToken(ctx context.Context, storage logical.Storage, key string) (*provider.Token, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.RLock()
	defer lock.RUnlock()

	return getAuthCodeTokenLocked(ctx, storage, key)
}

func (b *backend) refreshAuthCodeToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*provider.Token, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	// In case someone else refreshed this token from under us, we'll re-request
	// it here with the lock acquired.
	tok, err := getAuthCodeTokenLocked(ctx, storage, key)
	switch {
	case err != nil:
		return nil, err
	case tok == nil:
		return nil, nil
	case tokenValid(tok, data) || tok.RefreshToken == "":
		return tok, nil
	}

	tok.AccessToken = ""

	c, err := b.getCache(ctx, storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return nil, ErrNotConfigured
	}

	// Refresh.
	refreshed, err := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret).RefreshToken(ctx, tok)
	if err != nil {
		b.logger.Warn("unable to refresh token", "key", key, "error", err)
		return tok, nil
	}

	// Store the new token.
	entry, err := logical.StorageEntryJSON(key, refreshed)
	if err != nil {
		return nil, err
	}

	if err := storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return refreshed, nil
}

func (b *backend) getRefreshAuthCodeToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*provider.Token, error) {
	tok, err := b.getAuthCodeToken(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if tok == nil {
		return nil, nil
	}

	if !tokenValid(tok, data) {
		return b.refreshAuthCodeToken(ctx, storage, key, data)
	}

	return tok, nil
}

func (b *backend) refreshPeriodic(ctx context.Context, req *logical.Request) error {
	view := logical.NewStorageView(req.Storage, credsPathPrefix)
	return logical.ScanView(ctx, view, func(path string) {
		key := view.ExpandKey(path)

		if _, err := b.getRefreshAuthCodeToken(ctx, req.Storage, key, nil); err != nil {
			b.logger.Error("unable to refresh token", "key", key, "error", err)
		}
	})
}
