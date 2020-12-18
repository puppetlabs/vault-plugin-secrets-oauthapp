package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

type config struct {
	ClientID        string            `json:"client_id"`
	ClientSecret    string            `json:"client_secret"`
	AuthURLParams   map[string]string `json:"auth_url_params"`
	ProviderName    string            `json:"provider_name"`
	ProviderVersion int               `json:"provider_version"`
	ProviderOptions map[string]string `json:"provider_options"`
}

type cache struct {
	Config   *config
	Provider provider.Provider
	cancel   context.CancelFunc
}

func (c *cache) Close() {
	c.cancel()
}

func newCache(c *config, r *provider.Registry) (*cache, error) {
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
		entry, err := storage.Get(ctx, configPath)
		if err != nil {
			return nil, err
		} else if entry == nil {
			return nil, nil
		}

		cfg := &config{}
		if err := entry.DecodeJSON(cfg); err != nil {
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
