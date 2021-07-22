package backend

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/cache"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

type backend struct {
	*framework.Backend

	providerRegistry *provider.Registry
	clock            clock.Clock

	// scheduler is a worker that processes token renewals with hard schedules.
	// It will be created by the backend lifecycle in the initialize method.
	scheduler scheduler.StartedLifecycle

	// restartDescriptors causes managed descriptor to restart (when
	// configuration changes).
	restartDescriptors func()

	data  *persistence.Holder
	cache *cache.Cache
}

const backendHelp = `
The OAuth app backend provides OAuth authorization tokens on demand given a secret client configuration.
`

type Options struct {
	ProviderRegistry *provider.Registry
	Clock            clock.Clock
}

func New(opts Options) (logical.Backend, error) {
	providerRegistry := opts.ProviderRegistry
	if providerRegistry == nil {
		providerRegistry = provider.GlobalRegistry
	}

	clk := opts.Clock
	if clk == nil {
		clk = clock.RealClock
	}

	data := persistence.NewHolder()

	c, err := cache.NewCache(providerRegistry, data)
	if err != nil {
		return nil, err
	}

	b := &backend{
		providerRegistry: providerRegistry,
		clock:            clk,

		data:  data,
		cache: c,
	}
	b.Backend = &framework.Backend{
		Help:           strings.TrimSpace(backendHelp),
		PathsSpecial:   pathsSpecial(),
		Paths:          paths(b),
		BackendType:    logical.TypeLogical,
		InitializeFunc: b.initialize,
		Clean:          b.clean,
		Invalidate:     b.invalidate,
	}

	return b, nil
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := New(Options{})
	if err != nil {
		return nil, err
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}
