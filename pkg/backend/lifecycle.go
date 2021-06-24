package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
)

func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	refresh, restartRefresh := scheduler.NewRestartableDescriptor(&refreshDescriptor{backend: b, storage: req.Storage})

	b.scheduler = scheduler.NewSegment(16, []scheduler.Descriptor{
		scheduler.NewRecoveryDescriptor(
			&deviceCodeExchangeDescriptor{backend: b, storage: req.Storage},
			scheduler.RecoveryDescriptorWithClock(b.clock),
		),
		scheduler.NewRecoveryDescriptor(
			refresh,
			scheduler.RecoveryDescriptorWithClock(b.clock),
		),
	}).WithErrorBehavior(scheduler.ErrorBehaviorDrop).Start(scheduler.LifecycleStartOptions{})
	b.restartRefresh = restartRefresh

	return nil
}

func (b *backend) reset() {
	b.mut.Lock()
	defer b.mut.Unlock()

	if b.cache != nil {
		b.cache.Close()
		b.cache = nil
	}

	if b.restartRefresh != nil {
		b.restartRefresh()
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
