package backend

import (
	"context"
	"strings"
	"sync"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
)

type backend struct {
	providerRegistry *provider.Registry
	logger           hclog.Logger
	clock            clock.Clock

	// scheduler is a worker that processes token renewals with hard schedules.
	// It will be created by the backend lifecycle in the initialize method.
	scheduler scheduler.StartedLifecycle

	// restartRefresh causes the refresh descriptor to restart (when its
	// configuration changes).
	restartRefresh func()

	// mut protects the cache value.
	mut   sync.Mutex
	cache *cache

	// data is the API to the internal storage.
	data *persistence.Holder
}

const backendHelp = `
The OAuth app backend provides OAuth authorization tokens on demand given a secret client configuration.
`

type Options struct {
	ProviderRegistry *provider.Registry
	Logger           hclog.Logger
	Clock            clock.Clock
}

func New(opts Options) *framework.Backend {
	providerRegistry := opts.ProviderRegistry
	if providerRegistry == nil {
		providerRegistry = provider.GlobalRegistry
	}

	logger := opts.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	clk := opts.Clock
	if clk == nil {
		clk = clock.RealClock
	}

	b := &backend{
		providerRegistry: providerRegistry,
		logger:           logger,
		clock:            clk,

		data: persistence.NewHolder(),
	}

	return &framework.Backend{
		Help:           strings.TrimSpace(backendHelp),
		PathsSpecial:   pathsSpecial(),
		Paths:          paths(b),
		BackendType:    logical.TypeLogical,
		InitializeFunc: b.initialize,
		Clean:          b.clean,
		Invalidate:     b.invalidate,
	}
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := New(Options{Logger: conf.Logger})
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
