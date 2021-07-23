package framework

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/retry"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
)

type Upgrader interface {
	SentinelKey() string
	Upgrade(ctx context.Context) error
}

type UpgraderFactoryFunc func(data *persistence.Holder, storage logical.Storage) Upgrader

func Upgrade(ctx context.Context, factories []UpgraderFactoryFunc, data *persistence.Holder, storage logical.Storage, readOnly bool) error {
	if len(factories) == 0 {
		return nil
	}

	upgraders := make([]Upgrader, len(factories))
	for i, factory := range factories {
		upgraders[i] = factory(data, storage)
	}

	if readOnly {
		return pollForUpgrade(ctx, storage, upgraders[len(upgraders)-1])
	}

	return doUpgrade(ctx, storage, upgraders)
}

func pollForUpgrade(ctx context.Context, storage logical.Storage, lastUpgrader Upgrader) error {
	return retry.Wait(ctx, func(ctx context.Context) (bool, error) {
		if found, err := hasUpgrade(ctx, storage, lastUpgrader); err != nil {
			return retry.Done(fmt.Errorf("failed to poll for upgrades: %w", err))
		} else if !found {
			return retry.Repeat(fmt.Errorf("waiting for upgrades to complete"))
		}

		return retry.Done(nil)
	})
}

func doUpgrade(ctx context.Context, storage logical.Storage, upgraders []Upgrader) error {
	for _, upgrader := range upgraders {
		if found, err := hasUpgrade(ctx, storage, upgrader); err != nil {
			return fmt.Errorf("failed to check for upgrade sentinel using migration %s: %w", upgrader.SentinelKey(), err)
		} else if found {
			continue
		}

		if err := upgrader.Upgrade(ctx); err != nil {
			return fmt.Errorf("failed to upgrade using migration %s: %w", upgrader.SentinelKey(), err)
		}

		if err := putUpgradeSentinel(ctx, storage, upgrader); err != nil {
			return fmt.Errorf("failed to store upgrade sentinel using migration %s: %w", upgrader.SentinelKey(), err)
		}
	}

	return nil
}

func hasUpgrade(ctx context.Context, storage logical.Storage, upgrader Upgrader) (bool, error) {
	entry, err := storage.Get(ctx, fmt.Sprintf("upgrades/%s", upgrader.SentinelKey()))
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

func putUpgradeSentinel(ctx context.Context, storage logical.Storage, upgrader Upgrader) error {
	entry := &logical.StorageEntry{
		Key: fmt.Sprintf("upgrades/%s", upgrader.SentinelKey()),
	}
	return storage.Put(ctx, entry)
}
