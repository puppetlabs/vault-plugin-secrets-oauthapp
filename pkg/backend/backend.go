package backend

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

type backend struct {
	providerRegistry *provider.Registry
	logger           hclog.Logger

	// scheduler is a worker that processes token renewals with hard schedules.
	// It will be created by the backend lifecycle in the initialize method.
	scheduler scheduler.StartedLifecycle

	// mut protects the cache value.
	mut   sync.Mutex
	cache *cache

	// locks is a slice of mutexes that are used to protect credential updates.
	locks []*locksutil.LockEntry
}

const backendHelp = `
The OAuth app backend provides OAuth authorization tokens on demand given a secret client configuration.
`

type Options struct {
	ProviderRegistry *provider.Registry
	Logger           hclog.Logger
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

	b := &backend{
		providerRegistry: providerRegistry,
		logger:           logger,

		locks: locksutil.CreateLocks(),
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
