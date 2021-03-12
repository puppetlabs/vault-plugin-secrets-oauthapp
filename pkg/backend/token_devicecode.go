package backend

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/oauth2ext/semerr"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

type deviceCodeExchangeProcess struct {
	backend *backend
	storage logical.Storage
	key     string
}

var _ scheduler.Process = &deviceCodeExchangeProcess{}

func (dcep *deviceCodeExchangeProcess) Description() string {
	return fmt.Sprintf("device code exchange (%s)", dcep.key)
}

func (dcep *deviceCodeExchangeProcess) Run(ctx context.Context) error {
	return dcep.backend.getExchangeDeviceAuth(ctx, dcep.storage, dcep.key)
}

type deviceCodeExchangeDescriptor struct {
	backend *backend
	storage logical.Storage
}

var _ scheduler.Descriptor = &deviceCodeExchangeDescriptor{}

func (dced *deviceCodeExchangeDescriptor) Run(ctx context.Context, pc chan<- scheduler.Process) error {
	view := logical.NewStorageView(dced.storage, devicesPathPrefix)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		err := logical.ScanView(ctx, view, func(path string) {
			proc := &deviceCodeExchangeProcess{
				backend: dced.backend,
				storage: dced.storage,
				key:     view.ExpandKey(path),
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
		case <-ticker.C:
		case <-ctx.Done():
			return nil
		}
	}
}

func (b *backend) exchangeDeviceAuth(ctx context.Context, storage logical.Storage, key string) error {
	credKey := credsPathPrefix + strings.TrimPrefix(key, devicesPathPrefix)

	lock := locksutil.LockForKey(b.locks, credKey)
	lock.RLock()
	defer lock.RUnlock()

	// Get the underlying auth.
	auth, err := getDeviceAuthLocked(ctx, storage, key)
	if err != nil || auth == nil {
		return err
	}

	// Pull the credential now so we can decide of this attempt is even valid.
	ct, err := getCredTokenLocked(ctx, storage, credKey)
	switch {
	case err != nil:
		return err
	case ct == nil || ct.Issued() || ct.UserError != "":
		// Someone deleted the token from under us, updated it with a new
		// request, or it was never persisted in the first place. Just delete
		// this auth.
		return storage.Delete(ctx, key)
	}

	// Check the issue time one last time. Someone could have updated this from
	// under us as well.
	if auth.LastAttemptedIssueTime.Add(time.Duration(auth.Interval) * time.Second).After(time.Now()) {
		return nil
	}

	// We have a matching credential waiting to be issued.
	c, err := b.getCache(ctx, storage)
	if err != nil {
		return err
	} else if c == nil {
		return ErrNotConfigured
	}

	// Perform the exchange.
	tok, err := c.Provider.Public(c.Config.ClientID).DeviceCodeExchange(
		ctx,
		auth.DeviceCode,
		provider.WithProviderOptions(auth.ProviderOptions),
	)
	if err != nil {
		ct.LastAttemptedIssueTime = time.Now()
		auth.LastAttemptedIssueTime = ct.LastAttemptedIssueTime

		msg := errmap.Wrap(errmark.MarkShort(err), "device code exchange failed").Error()
		switch {
		case errmark.Matches(err, errmark.RuleType((*net.OpError)(nil))):
			// XXX: FIXME: Should be exponential backoff per RFC.
			auth.Interval += 5 // seconds
		case semerr.IsCode(err, "slow_down"):
			auth.Interval += 5 // seconds
		case semerr.IsCode(err, "authorization_pending"):
		case errmark.MarkedUser(err):
			ct.UserError = msg
		default:
			ct.TransientErrorsSinceLastIssue++
			ct.LastTransientError = msg
		}

		if ct.UserError != "" {
			entry, err := logical.StorageEntryJSON(key, auth)
			if err != nil {
				return err
			}

			if err := storage.Put(ctx, entry); err != nil {
				return err
			}
		}
	} else {
		ct.Token = tok
		ct.LastIssueTime = time.Now()
		ct.UserError = ""
		ct.TransientErrorsSinceLastIssue = 0
		ct.LastTransientError = ""
		ct.LastAttemptedIssueTime = time.Time{}
	}

	entry, err := logical.StorageEntryJSON(credKey, ct)
	if err != nil {
		return err
	}

	if err := storage.Put(ctx, entry); err != nil {
		return err
	}

	if ct.Issued() || ct.UserError != "" {
		// We're done here.
		if err := storage.Delete(ctx, key); err != nil {
			b.logger.Warn("failed to clean up stale device authentication request", "error", err)
		}
	}

	return nil
}

func (b *backend) getExchangeDeviceAuth(ctx context.Context, storage logical.Storage, key string) error {
	auth, err := b.getDeviceAuth(ctx, storage, key)
	switch {
	case err != nil:
		return err
	case auth == nil:
		return nil
	case auth.LastAttemptedIssueTime.Add(time.Duration(auth.Interval) * time.Second).After(time.Now()):
		// Waiting for next poll time to elapse.
		return nil
	default:
		return b.exchangeDeviceAuth(ctx, storage, key)
	}
}
