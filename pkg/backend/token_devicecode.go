package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/leg/timeutil/pkg/backoff"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/leg/timeutil/pkg/retry"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/semerr"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
)

type deviceCodeExchangeProcess struct {
	backend *backend
	storage logical.Storage
	keyer   persistence.AuthCodeKeyer
}

var _ scheduler.Process = &deviceCodeExchangeProcess{}

func (dcep *deviceCodeExchangeProcess) Description() string {
	return fmt.Sprintf("device code exchange (%s)", dcep.keyer.AuthCodeKey())
}

func (dcep *deviceCodeExchangeProcess) Run(ctx context.Context) error {
	return dcep.backend.getExchangeDeviceAuth(ctx, dcep.storage, dcep.keyer)
}

type deviceCodeExchangeDescriptor struct {
	backend *backend
	storage logical.Storage
}

var _ scheduler.Descriptor = &deviceCodeExchangeDescriptor{}

func (dced *deviceCodeExchangeDescriptor) Run(ctx context.Context, pc chan<- scheduler.Process) error {
	b := backoff.Build(
		backoff.Constant(time.Second),
		backoff.NonSliding,
	)
	err := retry.Wait(ctx, func(ctx context.Context) (bool, error) {
		err := dced.backend.data.AuthCode.Manager(dced.storage).ForEachDeviceAuthKey(ctx, func(keyer persistence.AuthCodeKeyer) error {
			proc := &deviceCodeExchangeProcess{
				backend: dced.backend,
				storage: dced.storage,
				keyer:   keyer,
			}

			select {
			case pc <- proc:
			case <-ctx.Done():
			}

			return nil
		})
		if err != nil {
			return retry.Done(err)
		}

		return retry.Repeat(nil)
	}, retry.WithClock(dced.backend.clock), retry.WithBackoffFactory(b))
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func (b *backend) exchangeDeviceAuth(ctx context.Context, storage logical.Storage, keyer persistence.AuthCodeKeyer) error {
	return b.data.AuthCode.WithLock(keyer, func(ch *persistence.LockedAuthCodeHolder) error {
		cm := ch.Manager(storage)

		// Get the underlying auth.
		auth, err := cm.ReadDeviceAuthEntry(ctx)
		if err != nil || auth == nil {
			return err
		}

		// Pull the credential now so we can decide of this attempt is even valid.
		ct, err := cm.ReadAuthCodeEntry(ctx)
		switch {
		case err != nil:
			return err
		case ct == nil || ct.TokenIssued() || ct.UserError != "":
			// Someone deleted the token from under us, updated it with a new
			// request, or it was never persisted in the first place. Just delete
			// this auth.
			return cm.DeleteAuthCodeEntry(ctx)
		}

		// Check the issue time one last time. Someone could have updated this from
		// under us as well.
		if !auth.ShouldPoll() {
			return nil
		}

		// We have a matching credential waiting to be issued.
		ops, put, err := b.getProviderOperations(ctx, storage, persistence.AuthServerName(ct.AuthServerName), defaultExpiryDelta)
		if errmark.MarkedUser(err) {
			ct.SetAuthServerError(errmark.MarkShort(err).Error())
		} else if err != nil {
			return err
		} else {
			defer put()

			// Perform the exchange.
			auth, ct, err = deviceAuthExchange(clockctx.WithClock(ctx, b.clock), ops, auth, ct)
			if err != nil {
				return err
			}

			// We need to run the auth exchange again, so go ahead and update it
			// now.
			if !ct.TokenIssued() && ct.UserError == "" {
				if err := cm.WriteDeviceAuthEntry(ctx, auth); err != nil {
					return err
				}
			}
		}

		// Update the underlying credential.
		if err := cm.WriteAuthCodeEntry(ctx, ct); err != nil {
			return err
		}

		// Opposite check -- if we did issue a token, we can delete the auth
		// request.
		if ct.TokenIssued() || ct.UserError != "" {
			// We're done here.
			if err := cm.DeleteDeviceAuthEntry(ctx); err != nil {
				b.Logger().Warn("failed to clean up stale device authentication request", "error", err)
			}
		}

		return nil
	})
}

func (b *backend) getExchangeDeviceAuth(ctx context.Context, storage logical.Storage, keyer persistence.AuthCodeKeyer) error {
	entry, err := b.data.AuthCode.Manager(storage).ReadDeviceAuthEntry(ctx, keyer)
	switch {
	case err != nil:
		return err
	case entry == nil:
		return nil
	case !entry.ShouldPoll():
		return nil
	default:
		return b.exchangeDeviceAuth(ctx, storage, keyer)
	}
}

func deviceAuthExchange(ctx context.Context, ops provider.PublicOperations, dae *persistence.DeviceAuthEntry, ace *persistence.AuthCodeEntry) (*persistence.DeviceAuthEntry, *persistence.AuthCodeEntry, error) {
	tok, err := ops.DeviceCodeExchange(
		ctx,
		dae.DeviceCode,
		provider.WithProviderOptions(dae.ProviderOptions),
	)
	if err != nil {
		msg := errmap.Wrap(errmark.MarkShort(err), "device code exchange failed").Error()
		switch {
		case errmark.Matches(err, errmark.RuleType((*net.OpError)(nil))):
			dae.Interval, err = deviceAuthNetworkErrorBackoff(ctx, dae.Interval)
			if err != nil {
				return nil, nil, err
			}
		case semerr.IsCode(err, "slow_down"):
			dae.Interval += 5 // seconds
		case semerr.IsCode(err, "authorization_pending"):
		case errmark.MarkedUser(err):
			ace.SetUserError(msg)
		default:
			ace.SetTransientError(msg)
		}

		dae.LastAttemptedIssueTime = ace.LastAttemptedIssueTime
	} else {
		ace.SetToken(tok)
	}

	return dae, ace, nil
}

func deviceAuthNetworkErrorBackoff(ctx context.Context, initial int32) (int32, error) {
	b, err := backoff.Once(
		backoff.Exponential(time.Duration(initial)*time.Second, 2),
		backoff.Jitter(0.1),
		backoff.MaxBound(5*time.Minute),
	)
	if err != nil {
		return 0, err
	}

	interval, err := b.Next(ctx)
	if err != nil {
		return 0, err
	}

	return int32(interval.Round(time.Second) / time.Second), nil
}
