package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/persistence"
)

const (
	refreshInterval = time.Minute
)

type refreshProcess struct {
	backend *backend
	storage logical.Storage
	keyer   persistence.AuthCodeKeyer
}

var _ scheduler.Process = &refreshProcess{}

func (rp *refreshProcess) Description() string {
	return fmt.Sprintf("credential refresh (%s)", rp.keyer.AuthCodeKey())
}

func (rp *refreshProcess) Run(ctx context.Context) error {
	_, err := rp.backend.getRefreshCredToken(ctx, rp.storage, rp.keyer, refreshInterval+10*time.Second)
	return err
}

type refreshDescriptor struct {
	backend *backend
	storage logical.Storage
}

var _ scheduler.Descriptor = &refreshDescriptor{}

func (rd *refreshDescriptor) Run(ctx context.Context, pc chan<- scheduler.Process) error {
	ticker := rd.backend.clock.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		err := rd.backend.data.Managers(rd.storage).AuthCode().ForEachAuthCodeKey(ctx, func(keyer persistence.AuthCodeKeyer) {
			proc := &refreshProcess{
				backend: rd.backend,
				storage: rd.storage,
				keyer:   keyer,
			}

			select {
			case pc <- proc:
			case <-ctx.Done():
			}
		})
		if err != nil {
			return err
		}

		select {
		case <-ticker.C():
		case <-ctx.Done():
			return nil
		}
	}
}

func (b *backend) refreshCredToken(ctx context.Context, storage logical.Storage, keyer persistence.AuthCodeKeyer, expiryDelta time.Duration) (*persistence.AuthCodeEntry, error) {
	var entry *persistence.AuthCodeEntry
	err := b.data.Managers(storage).AuthCode().WithLock(keyer, func(cm *persistence.LockedAuthCodeManager) error {
		// In case someone else refreshed this token from under us, we'll re-request
		// it here with the lock acquired.
		candidate, err := cm.ReadAuthCodeEntry(ctx)
		switch {
		case err != nil || candidate == nil:
			return err
		case !candidate.TokenIssued() || b.tokenValid(candidate.Token, expiryDelta) || candidate.RefreshToken == "":
			entry = candidate
			return nil
		}

		c, err := b.getCache(ctx, storage)
		if err != nil {
			return err
		} else if c == nil {
			return ErrNotConfigured
		}

		// Refresh.
		refreshed, err := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret).RefreshToken(ctx, candidate.Token)
		if err != nil {
			msg := errmap.Wrap(errmark.MarkShort(err), "refresh failed").Error()
			if errmark.MarkedUser(err) {
				candidate.SetUserError(msg)
			} else {
				candidate.SetTransientError(msg)
			}
		} else {
			candidate.SetToken(refreshed)
		}

		if err := cm.WriteAuthCodeEntry(ctx, candidate); err != nil {
			return err
		}

		entry = candidate
		return nil
	})
	return entry, err
}

func (b *backend) getRefreshCredToken(ctx context.Context, storage logical.Storage, keyer persistence.AuthCodeKeyer, expiryDelta time.Duration) (*persistence.AuthCodeEntry, error) {
	entry, err := b.data.Managers(storage).AuthCode().ReadAuthCodeEntry(ctx, keyer)
	switch {
	case err != nil:
		return nil, err
	case entry == nil:
		return nil, nil
	case !entry.TokenIssued() || b.tokenValid(entry.Token, expiryDelta):
		return entry, nil
	default:
		return b.refreshCredToken(ctx, storage, keyer, expiryDelta)
	}
}
