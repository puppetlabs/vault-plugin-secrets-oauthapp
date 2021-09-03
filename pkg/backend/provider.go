package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/cache"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
)

type publicAuthURLParamsOperations struct {
	provider.PublicOperations
	entry *persistence.AuthServerEntry
}

func (paupo *publicAuthURLParamsOperations) AuthCodeURL(state string, opts ...provider.AuthCodeURLOption) (string, bool) {
	opts = append([]provider.AuthCodeURLOption{}, opts...)
	opts = append(opts, provider.WithURLParams(paupo.entry.AuthURLParams))
	return paupo.PublicOperations.AuthCodeURL(state, opts...)
}

type privateAuthURLParamsOperations struct {
	provider.PrivateOperations
	entry *persistence.AuthServerEntry
}

func (paupo *privateAuthURLParamsOperations) AuthCodeURL(state string, opts ...provider.AuthCodeURLOption) (string, bool) {
	opts = append([]provider.AuthCodeURLOption{}, opts...)
	opts = append(opts, provider.WithURLParams(paupo.entry.AuthURLParams))
	return paupo.PrivateOperations.AuthCodeURL(state, opts...)
}

type providerOperations struct {
	entry    *persistence.AuthServerEntry
	provider provider.Provider
}

func (po *providerOperations) Public() provider.PublicOperations {
	return &publicAuthURLParamsOperations{
		PublicOperations: po.provider.Public(po.entry.ClientID),
		entry:            po.entry,
	}
}

func (po *providerOperations) Private() provider.PrivateOperations {
	return &privateAuthURLParamsOperations{
		PrivateOperations: po.provider.Private(po.entry.ClientID, po.entry.ClientSecret),
		entry:             po.entry,
	}
}

func (b *backend) getProviderOperations(ctx context.Context, storage logical.Storage, serverName string, expiryDelta time.Duration) (*providerOperations, func(), error) {
	cfg, err := b.cache.Config.Get(ctx, storage)
	if err != nil {
		return nil, nil, err
	}

	var server *cache.AuthServerCacheEntry
	if serverName == "" {
		keyer := persistence.AuthServerName("legacy")
		server, err = b.cache.AuthServer.Get(ctx, storage, keyer)
		if err == nil && server == nil {
			return nil, nil, fmt.Errorf("missing server, and no legacy server configured")
		}
	} else {
		keyer := persistence.AuthServerName(serverName)
		server, err = b.cache.AuthServer.Get(ctx, storage, keyer)
	}
	if err != nil {
		return nil, nil, err
	} else if server == nil {
		return nil, nil, errmark.MarkUser(ErrNoSuchServer)
	}

	tuning := persistence.DefaultConfigTuningEntry
	if cfg != nil {
		tuning = cfg.Tuning
	}

	p := server.Provider
	if tuning.ProviderTimeoutSeconds > 0 {
		p = provider.NewTimeoutProvider(
			p,
			provider.NewBoundedLogarithmicTimeoutAlgorithm(
				tuning.ProviderTimeoutExpiryLeewayFactor,
				time.Duration(tuning.ProviderTimeoutSeconds)*time.Second,
				expiryDelta,
			),
		)
	}

	ops := &providerOperations{
		entry:    server.AuthServerEntry,
		provider: p,
	}
	return ops, server.Put, nil
}
