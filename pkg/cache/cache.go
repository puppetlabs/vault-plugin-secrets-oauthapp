package cache

import (
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
)

const AuthServerCacheSize = 64

type Cache struct {
	Config     *ConfigCache
	AuthServer *AuthServerCache
}

func (c *Cache) InvalidateFromStorage(key string) (found bool) {
	found = found || c.Config.InvalidateFromStorage(key)
	found = found || c.AuthServer.InvalidateFromStorage(key)
	return
}

func (c *Cache) Purge() {
	c.Config.Purge()
	c.AuthServer.Purge()
}

func NewCache(providerRegistry *provider.Registry, data *persistence.Holder) (*Cache, error) {
	config := NewConfigCache(data.Config)

	authServer, err := NewAuthServerCache(AuthServerCacheSize, providerRegistry, data.AuthServer)
	if err != nil {
		return nil, err
	}

	return &Cache{
		Config:     config,
		AuthServer: authServer,
	}, nil
}
