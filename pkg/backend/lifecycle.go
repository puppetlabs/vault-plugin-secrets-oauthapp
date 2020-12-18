package backend

import "context"

func (b *backend) reset() {
	b.mut.Lock()
	defer b.mut.Unlock()

	if b.cache != nil {
		b.cache.Close()
		b.cache = nil
	}
}

func (b *backend) invalidate(ctx context.Context, key string) {
	if key == configPath {
		b.reset()
	}
}

func (b *backend) clean(ctx context.Context) {
	b.reset()
}
