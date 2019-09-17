package backend

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	credMut sync.Mutex
	logger  hclog.Logger
}

const backendHelp = `
The OAuth app backend provides OAuth authorization tokens on demand given a secret client configuration.
`

type Options struct {
	Logger hclog.Logger
}

func New(opts Options) *framework.Backend {
	logger := opts.Logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}

	b := &backend{
		logger: logger,
	}

	return &framework.Backend{
		Help:         strings.TrimSpace(backendHelp),
		PathsSpecial: pathsSpecial(),
		Paths:        paths(b),
		BackendType:  logical.TypeLogical,
		PeriodicFunc: b.refreshPeriodic,
	}
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := New(Options{Logger: conf.Logger})
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
