package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/upgrade/framework"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/upgrade/v2v3"
)

var upgrades = []framework.UpgraderFactoryFunc{
	v2v3.Factory,
}

func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	ownsStorage := b.ownsStorage()

	// Upgrade or wait for primary to upgrade.
	if err := framework.Upgrade(clockctx.WithClock(ctx, b.clock), upgrades, b.data, req.Storage, !ownsStorage); err != nil {
		return err
	}

	// Only start up the scheduler if we own the underlying storage, which isn't
	// the case for a variety of standby/secondary server configurations in
	// Vault Enterprise.
	if !ownsStorage {
		return nil
	}

	deviceCodeExchange := &deviceCodeExchangeDescriptor{backend: b, storage: req.Storage}
	refresh, restartRefresh := scheduler.NewRestartableDescriptor(&refreshDescriptor{backend: b, storage: req.Storage})
	reap, restartReap := scheduler.NewRestartableDescriptor(&reapDescriptor{backend: b, storage: req.Storage})

	b.scheduler = scheduler.NewSegment(16, []scheduler.Descriptor{
		scheduler.NewRecoveryDescriptor(deviceCodeExchange, scheduler.RecoveryDescriptorWithClock(b.clock)),
		scheduler.NewRecoveryDescriptor(refresh, scheduler.RecoveryDescriptorWithClock(b.clock)),
		scheduler.NewRecoveryDescriptor(reap, scheduler.RecoveryDescriptorWithClock(b.clock)),
	}).WithErrorBehavior(scheduler.ErrorBehaviorDrop).Start(scheduler.LifecycleStartOptions{})
	b.restartDescriptors = func() {
		restartRefresh()
		restartReap()
	}

	return nil
}

func (b *backend) reset() {
	if b.restartDescriptors != nil {
		b.restartDescriptors()
	}
}

func (b *backend) invalidate(ctx context.Context, key string) {
	b.cache.InvalidateFromStorage(key)

	if persistence.IsConfigKey(key) {
		b.reset()
	}
}

func (b *backend) clean(ctx context.Context) {
	// Shut down cache and provider.
	b.cache.Purge()

	// Shut down scheduler.
	if b.scheduler != nil {
		if err := scheduler.CloseWaitContext(ctx, b.scheduler); err != nil {
			b.Logger().Error("failed to shut down scheduler", "error", err)
		}
	}
}
