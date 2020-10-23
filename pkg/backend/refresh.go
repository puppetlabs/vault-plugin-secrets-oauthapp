package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
)

func tokenOk2Reuse(tok *oauth2.Token, data *framework.FieldData) bool {
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

func getToken(ctx context.Context, storage logical.Storage, key string) (*oauth2.Token, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	tok := &oauth2.Token{}
	if err := entry.DecodeJSON(tok); err != nil {
		return nil, err
	}

	return tok, nil
}

func (b *backend) refreshToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*oauth2.Token, error) {
	b.credMut.Lock()
	defer b.credMut.Unlock()

	// In case someone else refreshed this token from under us, we'll re-request
	// it here with the lock acquired.
	tok, err := getToken(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if tok == nil {
		return nil, nil
	} else if tokenOk2Reuse(tok, data) || tok.RefreshToken == "" {
		return tok, nil
	}
	tok.AccessToken = ""

	c, err := getConfig(ctx, storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return nil, ErrNotConfigured
	}

	p, err := c.provider(b.providerRegistry)
	if err != nil {
		return nil, err
	}

	// Refresh.
	src := p.NewExchangeConfigBuilder(c.ClientID, c.ClientSecret).
		Build().
		TokenSource(ctx, tok)

	refreshed, err := src.Token()
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

func (b *backend) getRefreshToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*oauth2.Token, error) {
	tok, err := getToken(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if tok == nil {
		return nil, nil
	}

	if !tokenOk2Reuse(tok, data) {
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
