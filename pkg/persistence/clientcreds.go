package persistence

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

const (
	clientCredsKeyPrefix = "self/"
)

type ClientCredsKeyer interface {
	// ClientCredsKey returns the storage key for storing ClientCredsEntry
	// objects.
	ClientCredsKey() string
}

type ClientCredsEntry struct {
	Token *provider.Token `json:"token"`

	Config struct {
		Scopes         []string          `json:"scopes"`
		TokenURLParams map[string]string `json:"token_url_params"`
	} `json:"config"`
}

type ClientCredsKey string

var _ ClientCredsKeyer = ClientCredsKey("")

func (ack ClientCredsKey) ClientCredsKey() string { return clientCredsKeyPrefix + string(ack) }

func ClientCredsName(name string) ClientCredsKeyer {
	hash := sha256.Sum224([]byte(name))
	first, second, rest := hash[:2], hash[2:4], hash[4:]
	return ClientCredsKey(fmt.Sprintf("%x/%x/%x", first, second, rest))
}

type LockedClientCredsManager struct {
	storage logical.Storage
	keyer   ClientCredsKeyer
}

func (lccm *LockedClientCredsManager) ReadClientCredsEntry(ctx context.Context) (*ClientCredsEntry, error) {
	se, err := lccm.storage.Get(ctx, lccm.keyer.ClientCredsKey())
	if err != nil {
		return nil, err
	} else if se == nil {
		return nil, nil
	}

	entry := &ClientCredsEntry{}
	if err := se.DecodeJSON(entry); err != nil {
		return nil, err
	}

	return entry, nil
}

func (lccm *LockedClientCredsManager) WriteClientCredsEntry(ctx context.Context, entry *ClientCredsEntry) error {
	se, err := logical.StorageEntryJSON(lccm.keyer.ClientCredsKey(), entry)
	if err != nil {
		return err
	}

	return lccm.storage.Put(ctx, se)
}

func (lccm *LockedClientCredsManager) DeleteClientCredsEntry(ctx context.Context) error {
	return lccm.storage.Delete(ctx, lccm.keyer.ClientCredsKey())
}

type ClientCredsManager struct {
	storage logical.Storage
	locks   []*locksutil.LockEntry
}

func (ccm *ClientCredsManager) WithLock(keyer ClientCredsKeyer, fn func(*LockedClientCredsManager) error) error {
	lock := locksutil.LockForKey(ccm.locks, keyer.ClientCredsKey())
	lock.Lock()
	defer lock.Unlock()

	return fn(&LockedClientCredsManager{
		storage: ccm.storage,
		keyer:   keyer,
	})
}

func (ccm *ClientCredsManager) ReadClientCredsEntry(ctx context.Context, keyer ClientCredsKeyer) (*ClientCredsEntry, error) {
	var entry *ClientCredsEntry
	err := ccm.WithLock(keyer, func(lccm *LockedClientCredsManager) (err error) {
		entry, err = lccm.ReadClientCredsEntry(ctx)
		return
	})
	return entry, err
}

func (ccm *ClientCredsManager) WriteClientCredsEntry(ctx context.Context, keyer ClientCredsKeyer, entry *ClientCredsEntry) error {
	return ccm.WithLock(keyer, func(lccm *LockedClientCredsManager) error {
		return lccm.WriteClientCredsEntry(ctx, entry)
	})
}

func (ccm *ClientCredsManager) DeleteClientCredsEntry(ctx context.Context, keyer ClientCredsKeyer) error {
	return ccm.WithLock(keyer, func(lccm *LockedClientCredsManager) error {
		return lccm.DeleteClientCredsEntry(ctx)
	})
}

func (ccm *ClientCredsManager) ForEachClientCredsKey(ctx context.Context, fn func(ClientCredsKeyer)) error {
	view := logical.NewStorageView(ccm.storage, clientCredsKeyPrefix)
	return logical.ScanView(ctx, view, func(path string) { fn(ClientCredsKey(path)) })
}
