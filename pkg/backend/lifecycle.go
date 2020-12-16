package backend

import "context"

func (b *backend) reset() {
	b.mut.Lock()
	defer b.mut.Unlock()

	if b.cacheCancel != nil {
		b.cacheCancel()
	}

	b.cache = nil
	b.cacheCancel = nil
}

func (b *backend) invalidate(ctx context.Context, key string) {
	switch key {
	case configPath:
		b.reset()
	}
}

func (b *backend) clean(ctx context.Context) {
	b.cancel()
}
