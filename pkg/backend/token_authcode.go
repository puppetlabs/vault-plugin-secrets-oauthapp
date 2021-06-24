package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/leg/timeutil/pkg/backoff"
	"github.com/puppetlabs/leg/timeutil/pkg/retry"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
)

type refreshProcess struct {
	backend     *backend
	storage     logical.Storage
	keyer       persistence.AuthCodeKeyer
	expiryDelta time.Duration
}

var _ scheduler.Process = &refreshProcess{}

func (rp *refreshProcess) Description() string {
	return fmt.Sprintf("credential refresh (%s)", rp.keyer.AuthCodeKey())
}

func (rp *refreshProcess) Run(ctx context.Context) error {
	_, err := rp.backend.getRefreshCredToken(ctx, rp.storage, rp.keyer, rp.expiryDelta)
	return err
}

type refreshDescriptor struct {
	backend *backend
	storage logical.Storage
}

var _ scheduler.Descriptor = &refreshDescriptor{}

func (rd *refreshDescriptor) Run(ctx context.Context, pc chan<- scheduler.Process) error {
	c, err := rd.backend.getCache(ctx, rd.storage)
	switch {
	case err != nil:
		return err
	case c == nil || c.Config.Tuning.RefreshCheckIntervalSeconds <= 0:
		return nil
	}

	refreshInterval := time.Duration(c.Config.Tuning.RefreshCheckIntervalSeconds) * time.Second

	b := backoff.Build(
		backoff.Constant(refreshInterval),
		backoff.NonSliding,
	)
	err = retry.Wait(ctx, func(ctx context.Context) (bool, error) {
		err := rd.backend.data.Managers(rd.storage).AuthCode().ForEachAuthCodeKey(ctx, func(keyer persistence.AuthCodeKeyer) {
			proc := &refreshProcess{
				backend:     rd.backend,
				storage:     rd.storage,
				keyer:       keyer,
				expiryDelta: refreshInterval + 10*time.Second,
			}

			select {
			case pc <- proc:
			case <-ctx.Done():
			}
		})
		if err != nil {
			return retry.Done(err)
		}

		return retry.Repeat(nil)
	}, retry.WithClock(rd.backend.clock), retry.WithBackoffFactory(b))
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
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
