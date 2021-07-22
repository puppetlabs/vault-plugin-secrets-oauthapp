package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

func (b *backend) updateClientCredsToken(ctx context.Context, storage logical.Storage, keyer persistence.ClientCredsKeyer, expiryDelta time.Duration) (*persistence.ClientCredsEntry, error) {
	var entry *persistence.ClientCredsEntry
	err := b.data.ClientCreds.WithLock(keyer, func(ch *persistence.LockedClientCredsHolder) error {
		cm := ch.Manager(storage)

		// In case someone else updated this token from under us, we'll re-request
		// it here with the lock acquired.
		candidate, err := cm.ReadClientCredsEntry(ctx)
		switch {
		case err != nil || candidate == nil:
			return err
		case b.tokenValid(candidate.Token, expiryDelta):
			entry = candidate
			return nil
		}

		ops, put, err := b.getProviderOperations(ctx, storage, persistence.AuthServerName(candidate.AuthServerName), expiryDelta)
		if err != nil {
			return err
		}
		defer put()

		updated, err := ops.Private().ClientCredentials(
			clockctx.WithClock(ctx, b.clock),
			provider.WithURLParams(candidate.Config.TokenURLParams),
			provider.WithScopes(candidate.Config.Scopes),
			provider.WithProviderOptions(candidate.Config.ProviderOptions),
		)
		if err != nil {
			return err
		}

		// Store the new creds.
		candidate.Token = updated

		if err := cm.WriteClientCredsEntry(ctx, candidate); err != nil {
			return err
		}

		entry = candidate
		return nil
	})
	return entry, err
}

func (b *backend) getUpdateClientCredsToken(ctx context.Context, storage logical.Storage, keyer persistence.ClientCredsKeyer, expiryDelta time.Duration) (*persistence.ClientCredsEntry, error) {
	entry, err := b.data.ClientCreds.Manager(storage).ReadClientCredsEntry(ctx, keyer)
	switch {
	case err != nil:
		return nil, err
	case entry != nil && b.tokenValid(entry.Token, expiryDelta):
		return entry, nil
	default:
		return b.updateClientCredsToken(ctx, storage, keyer, expiryDelta)
	}
}
