package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

type selfToken struct {
	Token *provider.Token `json:"token"`

	Config struct {
		Scopes         []string          `json:"scopes"`
		TokenURLParams map[string]string `json:"token_url_params"`
	} `json:"config"`
}

func getSelfTokenLocked(ctx context.Context, storage logical.Storage, key string) (*selfToken, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	cc := &selfToken{}
	if err := entry.DecodeJSON(cc); err != nil {
		return nil, err
	}

	return cc, nil
}

func (b *backend) getSelfToken(ctx context.Context, storage logical.Storage, key string) (*selfToken, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.RLock()
	defer lock.RUnlock()

	cc, err := getSelfTokenLocked(ctx, storage, key)
	if err != nil {
		return nil, err
	}

	return cc, nil
}
