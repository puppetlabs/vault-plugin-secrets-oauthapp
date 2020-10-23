package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/oauth2"
)

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

func (b *backend) refreshToken(ctx context.Context, storage logical.Storage, key string, scopes []string) (*oauth2.Token, error) {
	b.credMut.Lock()
	defer b.credMut.Unlock()

	// In case someone else refreshed this token from under us, we'll re-request
	// it here with the lock acquired.
	tok, err := getToken(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if tok == nil {
		return nil, nil
	} else if tok.Valid() {
		return tok, nil
	}

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
	var src oauth2.TokenSource
	if p.IsAuthorizationRequired() {
		// 2-legged OAuth does not use refresh token.
		// This check is relevant only with 3-legged OAuth
		if tok.RefreshToken == "" {
			return tok, nil
		}

		src = p.NewExchangeConfigBuilder(c.ClientID, c.ClientSecret).
			Build().
			TokenSource(ctx, tok)
	} else {
		cb, err := p.NewTokenConfigBuilder(c.ClientID, c.ClientSecret)
		if err != nil {
			return nil, err
		}

		if scopes != nil {
			cb.WithScopes(scopes...)
		}

		src = cb.Build().TokenSource(ctx)
	}

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

func (b *backend) getRefreshToken(ctx context.Context, storage logical.Storage, key string, scopes []string, isPeriodicRefresh bool) (*oauth2.Token, error) {
	tok, err := getToken(ctx, storage, key)
	if err != nil {
		return nil, err
	} else if tok == nil {
		// Token is not stored yet.
		// Try 2-legged OAuth, if the provider supports it.
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

		// Return if this is not 2-legged OAuth or is periodic refresh
		if p.IsAuthorizationRequired() || isPeriodicRefresh {
			return nil, nil
		}

		cb, err := p.NewTokenConfigBuilder(c.ClientID, c.ClientSecret)
		if err != nil {
			return nil, err
		}

		if scopes != nil {
			cb.WithScopes(scopes...)
		}

		// Get new token
		tok, err = cb.Build().Token(ctx)
		if rErr, ok := err.(*oauth2.RetrieveError); ok {
			b.logger.Error("invalid client credentials", "error", rErr)
			return nil, ErrInvalidCredentials
		} else if err != nil {
			return nil, err
		}

		b.credMut.Lock()
		defer b.credMut.Unlock()

		// TODO: Handle extra fields?
		entry, err := logical.StorageEntryJSON(key, tok)
		if err != nil {
			return nil, err
		}

		if err := storage.Put(ctx, entry); err != nil {
			return nil, err
		}
	}

	if !tok.Valid() {
		return b.refreshToken(ctx, storage, key, scopes)
	}

	return tok, nil
}

func (b *backend) refreshPeriodic(ctx context.Context, req *logical.Request) error {
	view := logical.NewStorageView(req.Storage, credsPathPrefix)
	logical.ScanView(ctx, view, func(path string) {
		key := view.ExpandKey(path)

		if _, err := b.getRefreshToken(ctx, req.Storage, key, nil, true); err != nil {
			b.logger.Error("unable to refresh token", "key", key, "error", err)
		}
	})

	return nil
}
