package backend

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestBackendNew(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b, err := Factory(ctx, &logical.BackendConfig{})
	require.NoError(t, err)
	require.NotNil(t, b)
}
