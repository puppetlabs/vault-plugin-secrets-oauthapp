package backend

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type deviceAuth struct {
	DeviceCode             string            `json:"device_code"`
	Interval               int32             `json:"interval"`
	LastAttemptedIssueTime time.Time         `json:"last_attempted_issue_time"`
	ProviderOptions        map[string]string `json:"provider_options"`
}

func getDeviceAuthLocked(ctx context.Context, storage logical.Storage, key string) (*deviceAuth, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	auth := &deviceAuth{}
	if err := entry.DecodeJSON(auth); err != nil {
		return nil, err
	}

	return auth, nil
}

func (b *backend) getDeviceAuth(ctx context.Context, storage logical.Storage, key string) (*deviceAuth, error) {
	lockKey := credsPathPrefix + strings.TrimPrefix(key, devicesPathPrefix)

	lock := locksutil.LockForKey(b.locks, lockKey)
	lock.RLock()
	defer lock.RUnlock()

	return getDeviceAuthLocked(ctx, storage, key)
}
