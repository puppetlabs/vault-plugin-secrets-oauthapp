package backend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/leg/timeutil/pkg/backoff"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/leg/timeutil/pkg/retry"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/reap"
)

type reapProcess struct {
	backend *backend
	storage logical.Storage
	keyer   persistence.AuthCodeKeyer
	dryRun  bool
	checker *reap.AuthCodeChecker
}

var _ scheduler.Process = &reapProcess{}

func (rp *reapProcess) Description() string {
	return fmt.Sprintf("credential reap (%s)", rp.keyer.AuthCodeKey())
}

func (rp *reapProcess) Run(ctx context.Context) error {
	return rp.backend.data.Managers(rp.storage).AuthCode().WithLock(rp.keyer, func(cm *persistence.LockedAuthCodeManager) error {
		entry, err := cm.ReadAuthCodeEntry(ctx)
		if err != nil || entry == nil {
			return err
		}

		err = rp.checker.Check(clockctx.WithClock(ctx, rp.backend.clock), entry)
		if err == nil {
			return nil
		}

		if rp.dryRun {
			rp.backend.logger.Info("credential would have been deleted by reaping (dry run)", "key", rp.keyer.AuthCodeKey(), "cause", err)
			return nil
		}

		if err := cm.DeleteAuthCodeEntry(ctx); err != nil {
			return err
		}

		rp.backend.logger.Debug("credential deleted by reaping", "key", rp.keyer.AuthCodeKey(), "cause", err)
		return nil
	})
}

type reapDescriptor struct {
	backend *backend
	storage logical.Storage
}

var _ scheduler.Descriptor = &reapDescriptor{}

func (rd *reapDescriptor) Run(ctx context.Context, pc chan<- scheduler.Process) error {
	c, err := rd.backend.getCache(ctx, rd.storage)
	switch {
	case err != nil:
		return err
	case c == nil || c.Config.Tuning.ReapCheckIntervalSeconds <= 0:
		return nil
	}

	interval := time.Duration(c.Config.Tuning.ReapCheckIntervalSeconds) * time.Second
	checker := reap.NewAuthCodeChecker(c.Config)

	b := backoff.Build(
		backoff.Constant(interval),
		backoff.NonSliding,
	)
	err = retry.Wait(ctx, func(ctx context.Context) (bool, error) {
		rd.backend.logger.Debug("running credential reap")

		err := rd.backend.data.Managers(rd.storage).AuthCode().ForEachAuthCodeKey(ctx, func(keyer persistence.AuthCodeKeyer) {
			proc := &reapProcess{
				backend: rd.backend,
				storage: rd.storage,
				keyer:   keyer,
				dryRun:  c.Config.Tuning.ReapDryRun,
				checker: checker,
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
