package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

type cache struct {
	Config   *persistence.ConfigEntry
	Provider provider.Provider
	cancel   context.CancelFunc
}

func (c *cache) Close() {
	c.cancel()
}

func newCache(c *persistence.ConfigEntry, r *provider.Registry) (*cache, error) {
	ctx, cancel := context.WithCancel(context.Background())

	p, err := r.NewAt(ctx, c.ProviderName, c.ProviderVersion, c.ProviderOptions)
	if err != nil {
		cancel()
		return nil, err
	}

	return &cache{
		Config:   c,
		Provider: p,
		cancel:   cancel,
	}, nil
}

func (b *backend) getCache(ctx context.Context, storage logical.Storage) (*cache, error) {
	b.mut.Lock()
	defer b.mut.Unlock()

	if b.cache == nil {
		cfg, err := b.data.Managers(storage).Config().ReadConfig(ctx)
		if err != nil || cfg == nil {
			return nil, err
		}

		cache, err := newCache(cfg, b.providerRegistry)
		if err != nil {
			return nil, err
		}

		b.cache = cache
	}

	return b.cache, nil
}
