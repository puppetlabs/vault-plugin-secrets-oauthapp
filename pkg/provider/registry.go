package provider

import (
	"context"
	"fmt"
	"sync"
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
		return fmt.Errorf("provider: factory with name %q already exists", name)
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

	p, found := r.factories[name]
	if !found {
		return nil, ErrNoSuchProvider
	}

	return p(ctx, vsn, opts)
}

func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]FactoryFunc),
	}
}
