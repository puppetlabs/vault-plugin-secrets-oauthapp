package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

func tokenValid(tok *provider.Token, data *framework.FieldData) bool {
	if !tok.Valid() {
		return false
	}
	if data == nil {
		return true
	}
	if minsecondsstr, ok := data.GetOk("minimum_seconds"); ok {
		minseconds := minsecondsstr.(int)
		zeroTime := time.Time{}
		if tok.Expiry != zeroTime && time.Until(tok.Expiry).Seconds() < float64(minseconds) {
			return false
		}
	}
	return true
}

func getTokenLocked(ctx context.Context, storage logical.Storage, key string) (*provider.Token, error) {
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

func (b *backend) getToken(ctx context.Context, storage logical.Storage, key string) (*provider.Token, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.RLock()
	defer lock.RUnlock()

	return getTokenLocked(ctx, storage, key)
}

func (b *backend) refreshToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*provider.Token, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	// In case someone else refreshed this token from under us, we'll re-request
	// it here with the lock acquired.
	tok, err := getTokenLocked(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if tok == nil {
		return nil, nil
	} else if tokenValid(tok, data) || tok.RefreshToken == "" {
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
	refreshed, err := c.Provider.NewExchangeConfigBuilder(c.Config.ClientID, c.Config.ClientSecret).
		Build().
		Refresh(ctx, tok)
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

func (b *backend) getRefreshToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*provider.Token, error) {
	tok, err := b.getToken(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if tok == nil {
		return nil, nil
	}

	if !tokenValid(tok, data) {
		return b.refreshToken(ctx, storage, key, data)
	}

	return tok, nil
}

func (b *backend) refreshPeriodic(ctx context.Context, req *logical.Request) error {
	view := logical.NewStorageView(req.Storage, credsPathPrefix)
	logical.ScanView(ctx, view, func(path string) {
		key := view.ExpandKey(path)

		if _, err := b.getRefreshToken(ctx, req.Storage, key, nil); err != nil {
			b.logger.Error("unable to refresh token", "key", key, "error", err)
		}
	})

	return nil
}
