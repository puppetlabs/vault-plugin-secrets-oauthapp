package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
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

func (b *backend) getProviderOperations(ctx context.Context, storage logical.Storage, keyer persistence.AuthServerKeyer, expiryDelta time.Duration) (*providerOperations, func(), error) {
	cfg, err := b.cache.Config.Get(ctx, storage)
	if err != nil {
		return nil, nil, err
	}

	server, err := b.cache.AuthServer.Get(ctx, storage, keyer)
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
