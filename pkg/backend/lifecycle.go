package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
)

func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
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
	b.mut.Lock()
	defer b.mut.Unlock()

	if b.cache != nil {
		b.cache.Close()
		b.cache = nil
	}

	if b.restartDescriptors != nil {
		b.restartDescriptors()
	}
}

func (b *backend) invalidate(ctx context.Context, key string) {
	if persistence.IsConfigKey(key) {
		b.reset()
	}
}

func (b *backend) clean(ctx context.Context) {
	// Shut down cache and provider.
	b.reset()

	// Shut down scheduler.
	if b.scheduler != nil {
		if err := scheduler.CloseWaitContext(ctx, b.scheduler); err != nil {
			b.logger.Error("failed to shut down scheduler", "error", err)
		}
	}
}
