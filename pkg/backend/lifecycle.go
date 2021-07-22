package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/helper/pluginutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
)

func (b *backend) Setup(ctx context.Context, conf *logical.BackendConfig) error {
	if err := b.Backend.Setup(ctx, conf); err != nil {
		return err
	}

	// Do not manipulate storage or track migration status.
	if pluginutil.InMetadataMode() {
		return nil
	}

	// XXX: TODO: Add automatic migrations here.

	return nil
}

func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	// Only start up the scheduler if we own the underlying storage, which isn't
	// the case for a variety of standby/secondary server configurations in
	// Vault Enterprise.
	if !b.ownsStorage() {
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
