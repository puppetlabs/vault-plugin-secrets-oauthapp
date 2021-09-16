package backend

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
)

func (b *backend) getServerNameOrDefault(ctx context.Context, storage logical.Storage, name string) (string, error) {
	if name != "" {
		return name, nil
	}

	cfg, err := b.cache.Config.Get(ctx, storage)
	if err != nil {
		return "", err
	} else if cfg == nil || cfg.DefaultServer == "" {
		return "", errmark.MarkUser(ErrMissingServerField)
	}

	return cfg.DefaultServer, nil
}
