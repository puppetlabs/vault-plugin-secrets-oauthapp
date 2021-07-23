package vaultext_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/vaultext"
	"github.com/stretchr/testify/require"
)

func TestScanViewUserError(t *testing.T) {
	ctx := context.Background()

	storage := &logical.InmemStorage{}
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{Key: "test/a"}))
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{Key: "test/b"}))
	require.NoError(t, storage.Put(ctx, &logical.StorageEntry{Key: "test/c"}))

	var i int
	err := vaultext.ScanView(ctx, storage, func(path string) error {
		i++
		if i > 1 {
			return fmt.Errorf("too big: %d", i)
		}

		return nil
	})
	require.Equal(t, 2, i)
	require.EqualError(t, err, "too big: 2")
}
