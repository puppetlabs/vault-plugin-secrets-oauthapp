package vaultext

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

func ScanView(ctx context.Context, view logical.ClearableView, fn func(path string) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var uerr error
	err := logical.ScanView(ctx, view, func(path string) {
		if uerr == nil {
			uerr = fn(path)
		}
		if uerr != nil {
			cancel()
		}
	})
	if uerr != nil {
		return uerr
	} else if err != nil {
		return err
	}

	return nil
}
