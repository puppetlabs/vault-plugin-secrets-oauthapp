package provider

import (
	"context"
	"fmt"
)

func init() {
	GlobalRegistry.MustRegister("oidc", oidcFactory)
}

func oidcFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 1)

	return nil, fmt.Errorf("not implemented")
}
