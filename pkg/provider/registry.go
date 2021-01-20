package provider

import (
	"context"
	"fmt"
	"sync"

	"github.com/puppetlabs/leg/errmap/pkg/errmark"
)

type FactoryFunc func(ctx context.Context, vsn int, opts map[string]string) (Provider, error)

type Registry struct {
	factories map[string]FactoryFunc
	mut       sync.RWMutex
}

// Register registers a new provider using the name and factory specified.
func (r *Registry) Register(name string, factory FactoryFunc) error {
	r.mut.Lock()
	defer r.mut.Unlock()

	if _, found := r.factories[name]; found {
		return fmt.Errorf("factory with name %q already exists", name)
	}

	r.factories[name] = factory

	return nil
}

func (r *Registry) MustRegister(name string, factory FactoryFunc) {
	if err := r.Register(name, factory); err != nil {
		panic(err)
	}
}

// New looks up a provider with the given name and configures it according to
// the specified options.
func (r *Registry) New(ctx context.Context, name string, opts map[string]string) (Provider, error) {
	return r.NewAt(ctx, name, -1, opts)
}

// NewAt looks up a provider with the given name at the given version and
// configures it according to the specified options.
func (r *Registry) NewAt(ctx context.Context, name string, vsn int, opts map[string]string) (Provider, error) {
	r.mut.RLock()
	defer r.mut.RUnlock()

	fn, found := r.factories[name]
	if !found {
		return nil, errmark.MarkUser(ErrNoSuchProvider)
	}

	p, err := fn(ctx, vsn, opts)
	if err != nil {
		return nil, errmark.MarkUserIf(err, errmark.RuleAny(
			errmark.RuleIs(ErrNoProviderWithVersion),
			errmark.RuleIs(ErrNoOptions),
			errmark.RuleType(&OptionError{}),
		))
	}

	return p, nil
}

func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]FactoryFunc),
	}
}
