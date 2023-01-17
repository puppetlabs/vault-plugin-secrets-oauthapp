package persistence

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/vaultext"
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

	// AuthServerName is the authorization server we should use to handle this
	// entry.
	AuthServerName string `json:"auth_server_name"`

	// MaximumExpirySeconds caps issued auth tokens to a desired lifetime.
	MaximumExpirySeconds int `json:"maximum_expiry_seconds,omitempty"`

	Config struct {
		Scopes          []string          `json:"scopes"`
		TokenURLParams  map[string]string `json:"token_url_params"`
		ProviderOptions map[string]string `json:"provider_options"`
	} `json:"config"`
}

func (cce *ClientCredsEntry) SetToken(ctx context.Context, tok *provider.Token) {
	cce.Token = tok
	if cce.MaximumExpirySeconds != 0 {
		maximumExpiry := clockctx.Clock(ctx).Now().Add(time.Duration(cce.MaximumExpirySeconds) * time.Second)
		if cce.Token.Expiry.IsZero() || cce.Token.Expiry.After(maximumExpiry) {
			cce.Token.Expiry = maximumExpiry
		}
	}
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

	// UPGRADING (v2): Set the server name to the default legacy server if it is
	// not present here.
	if entry.AuthServerName == "" {
		entry.AuthServerName = LegacyAuthServerName
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

type LockedClientCredsHolder struct {
	keyer ClientCredsKeyer
}

func (lcch *LockedClientCredsHolder) Manager(storage logical.Storage) *LockedClientCredsManager {
	return &LockedClientCredsManager{
		storage: storage,
		keyer:   lcch.keyer,
	}
}

type ClientCredsLocker interface {
	WithLock(ClientCredsKeyer, func(*LockedClientCredsHolder) error) error
}

type ClientCredsManager struct {
	storage logical.Storage
	locker  ClientCredsLocker
}

func (ccm *ClientCredsManager) ReadClientCredsEntry(ctx context.Context, keyer ClientCredsKeyer) (*ClientCredsEntry, error) {
	var entry *ClientCredsEntry
	err := ccm.locker.WithLock(keyer, func(lcch *LockedClientCredsHolder) (err error) {
		entry, err = lcch.Manager(ccm.storage).ReadClientCredsEntry(ctx)
		return
	})
	return entry, err
}

func (ccm *ClientCredsManager) WriteClientCredsEntry(ctx context.Context, keyer ClientCredsKeyer, entry *ClientCredsEntry) error {
	return ccm.locker.WithLock(keyer, func(lcch *LockedClientCredsHolder) error {
		return lcch.Manager(ccm.storage).WriteClientCredsEntry(ctx, entry)
	})
}

func (ccm *ClientCredsManager) DeleteClientCredsEntry(ctx context.Context, keyer ClientCredsKeyer) error {
	return ccm.locker.WithLock(keyer, func(lcch *LockedClientCredsHolder) error {
		return lcch.Manager(ccm.storage).DeleteClientCredsEntry(ctx)
	})
}

func (ccm *ClientCredsManager) ForEachClientCredsKey(ctx context.Context, fn func(ClientCredsKeyer) error) error {
	view := logical.NewStorageView(ccm.storage, clientCredsKeyPrefix)
	return vaultext.ScanView(ctx, view, func(path string) error { return fn(ClientCredsKey(path)) })
}

type ClientCredsHolder struct {
	locks []*locksutil.LockEntry
}

func (cch *ClientCredsHolder) WithLock(keyer ClientCredsKeyer, fn func(*LockedClientCredsHolder) error) error {
	lock := locksutil.LockForKey(cch.locks, keyer.ClientCredsKey())
	lock.Lock()
	defer lock.Unlock()

	return fn(&LockedClientCredsHolder{
		keyer: keyer,
	})
}

func (cch *ClientCredsHolder) Manager(storage logical.Storage) *ClientCredsManager {
	return &ClientCredsManager{
		storage: storage,
		locker:  cch,
	}
}
