// TODO: We should upgrade credential keys to use a cryptographically secure
// hash algorithm.
/* #nosec G401 G505 */

package persistence

import (
	"context"
	"crypto/sha1"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/vaultext"
)

const (
	authCodeKeyPrefix   = "creds/"
	deviceAuthKeyPrefix = "devices/"
)

type AuthCodeKeyer interface {
	// AuthCodeKey returns the storage key for storing AuthCodeEntry objects.
	AuthCodeKey() string

	// DeviceAuthKey returns the storage key for storing DeviceAuthEntry
	// objects.
	DeviceAuthKey() string
}

type AuthCodeEntry struct {
	// We embed a *provider.Token as the base type. This ensures compatibility
	// and keeps storage size reasonable because this will be the default
	// configuration.
	*provider.Token `json:",inline"`

	// AuthServerName is the authorization server we should use to handle this
	// entry.
	AuthServerName string `json:"auth_server_name"`

	// MaximumExpirySeconds caps issued auth tokens to a desired lifetime.
	MaximumExpirySeconds int `json:"maximum_expiry_seconds,omitempty"`

	// LastIssueTime is the most recent time a token was successfully issued.
	LastIssueTime time.Time `json:"last_issue_time,omitempty"`

	// AuthServerError indicates that the actual backing server and provider
	// could not be acquired to make this token request.
	AuthServerError string `json:"auth_server_error,omitempty"`

	// UserError is used to store a permanent error that indicates the end of
	// this token's usable lifespan.
	UserError string `json:"user_error,omitempty"`

	// TransientErrorsSinceLastIssue is a counter of the number of transient
	// errors encountered since the last time the token was successfully issued
	// (either originally or by refresh).
	TransientErrorsSinceLastIssue int `json:"transient_errors_since_last_issue,omitempty"`

	// If TransientErrorsSinceLastIssue > 0, this holds the last transient error
	// encountered to include as a warning (if the token is still valid) or
	// error on the response.
	LastTransientError string `json:"last_transient_error,omitempty"`

	// If the most recent exchange did not succeed, this holds the time that
	// exchange occurred.
	LastAttemptedIssueTime time.Time `json:"last_attempted_issue_time,omitempty"`
}

func (ace *AuthCodeEntry) SetToken(ctx context.Context, tok *provider.Token) {
	ace.Token = tok
	ace.LastIssueTime = clockctx.Clock(ctx).Now()
	if ace.MaximumExpirySeconds != 0 {
		maximumExpiry := ace.LastIssueTime.Add(time.Duration(ace.MaximumExpirySeconds) * time.Second)
		if ace.Expiry.IsZero() || ace.Expiry.After(maximumExpiry) {
			ace.Expiry = maximumExpiry
		}
	}
	ace.AuthServerError = ""
	ace.UserError = ""
	ace.TransientErrorsSinceLastIssue = 0
	ace.LastTransientError = ""
	ace.LastAttemptedIssueTime = time.Time{}
}

func (ace *AuthCodeEntry) SetAuthServerError(ctx context.Context, err string) {
	ace.AuthServerError = err
	ace.LastAttemptedIssueTime = clockctx.Clock(ctx).Now()
}

func (ace *AuthCodeEntry) SetUserError(ctx context.Context, err string) {
	ace.AuthServerError = ""
	ace.UserError = err
	ace.LastAttemptedIssueTime = clockctx.Clock(ctx).Now()
}

func (ace *AuthCodeEntry) SetTransientError(ctx context.Context, err string) {
	ace.AuthServerError = ""
	ace.TransientErrorsSinceLastIssue++
	ace.LastTransientError = err
	ace.LastAttemptedIssueTime = clockctx.Clock(ctx).Now()
}

// TokenIssued indicates whether a token has been issued at all.
//
// For certain grant types, like device code flow, we may not have an access
// token yet. In that case, we must wait for a polling process to update this
// value. A temporary error will be returned.
func (ace *AuthCodeEntry) TokenIssued() bool {
	return ace.Token != nil && ace.AccessToken != ""
}

type DeviceAuthEntry struct {
	DeviceCode             string            `json:"device_code"`
	Interval               int32             `json:"interval"`
	LastAttemptedIssueTime time.Time         `json:"last_attempted_issue_time"`
	ProviderOptions        map[string]string `json:"provider_options"`
}

func (dae *DeviceAuthEntry) ShouldPoll(ctx context.Context) bool {
	return dae.LastAttemptedIssueTime.Add(time.Duration(dae.Interval) * time.Second).Before(clockctx.Clock(ctx).Now())
}

type AuthCodeKey string

var _ AuthCodeKeyer = AuthCodeKey("")

func (ack AuthCodeKey) AuthCodeKey() string   { return authCodeKeyPrefix + string(ack) }
func (ack AuthCodeKey) DeviceAuthKey() string { return deviceAuthKeyPrefix + string(ack) }

func AuthCodeName(name string) AuthCodeKeyer {
	hash := sha1.Sum([]byte(name))
	first, second, rest := hash[:2], hash[2:4], hash[4:]
	return AuthCodeKey(fmt.Sprintf("%x/%x/%x", first, second, rest))
}

type LockedAuthCodeManager struct {
	storage logical.Storage
	keyer   AuthCodeKeyer
}

func (lacm *LockedAuthCodeManager) ReadAuthCodeEntry(ctx context.Context) (*AuthCodeEntry, error) {
	se, err := lacm.storage.Get(ctx, lacm.keyer.AuthCodeKey())
	if err != nil {
		return nil, err
	} else if se == nil {
		return nil, nil
	}

	entry := &AuthCodeEntry{}
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

func (lacm *LockedAuthCodeManager) ReadDeviceAuthEntry(ctx context.Context) (*DeviceAuthEntry, error) {
	se, err := lacm.storage.Get(ctx, lacm.keyer.DeviceAuthKey())
	if err != nil {
		return nil, err
	} else if se == nil {
		return nil, nil
	}

	entry := &DeviceAuthEntry{}
	if err := se.DecodeJSON(entry); err != nil {
		return nil, err
	}

	return entry, nil
}

func (lacm *LockedAuthCodeManager) WriteAuthCodeEntry(ctx context.Context, entry *AuthCodeEntry) error {
	se, err := logical.StorageEntryJSON(lacm.keyer.AuthCodeKey(), entry)
	if err != nil {
		return err
	}

	return lacm.storage.Put(ctx, se)
}

func (lacm *LockedAuthCodeManager) WriteDeviceAuthEntry(ctx context.Context, entry *DeviceAuthEntry) error {
	se, err := logical.StorageEntryJSON(lacm.keyer.DeviceAuthKey(), entry)
	if err != nil {
		return err
	}

	return lacm.storage.Put(ctx, se)
}

func (lacm *LockedAuthCodeManager) DeleteAuthCodeEntry(ctx context.Context) error {
	return lacm.storage.Delete(ctx, lacm.keyer.AuthCodeKey())
}

func (lacm *LockedAuthCodeManager) DeleteDeviceAuthEntry(ctx context.Context) error {
	return lacm.storage.Delete(ctx, lacm.keyer.DeviceAuthKey())
}

type LockedAuthCodeHolder struct {
	keyer AuthCodeKeyer
}

func (lach *LockedAuthCodeHolder) Manager(storage logical.Storage) *LockedAuthCodeManager {
	return &LockedAuthCodeManager{
		storage: storage,
		keyer:   lach.keyer,
	}
}

type AuthCodeLocker interface {
	WithLock(AuthCodeKeyer, func(*LockedAuthCodeHolder) error) error
}

type AuthCodeManager struct {
	storage logical.Storage
	locker  AuthCodeLocker
}

func (acm *AuthCodeManager) ReadAuthCodeEntry(ctx context.Context, keyer AuthCodeKeyer) (*AuthCodeEntry, error) {
	var entry *AuthCodeEntry
	err := acm.locker.WithLock(keyer, func(lach *LockedAuthCodeHolder) (err error) {
		entry, err = lach.Manager(acm.storage).ReadAuthCodeEntry(ctx)
		return
	})
	return entry, err
}

func (acm *AuthCodeManager) ReadDeviceAuthEntry(ctx context.Context, keyer AuthCodeKeyer) (*DeviceAuthEntry, error) {
	var entry *DeviceAuthEntry
	err := acm.locker.WithLock(keyer, func(lach *LockedAuthCodeHolder) (err error) {
		entry, err = lach.Manager(acm.storage).ReadDeviceAuthEntry(ctx)
		return
	})
	return entry, err
}

func (acm *AuthCodeManager) WriteAuthCodeEntry(ctx context.Context, keyer AuthCodeKeyer, entry *AuthCodeEntry) error {
	return acm.locker.WithLock(keyer, func(lach *LockedAuthCodeHolder) error {
		return lach.Manager(acm.storage).WriteAuthCodeEntry(ctx, entry)
	})
}

func (acm *AuthCodeManager) WriteDeviceAuthEntry(ctx context.Context, keyer AuthCodeKeyer, entry *DeviceAuthEntry) error {
	return acm.locker.WithLock(keyer, func(lach *LockedAuthCodeHolder) error {
		return lach.Manager(acm.storage).WriteDeviceAuthEntry(ctx, entry)
	})
}

func (acm *AuthCodeManager) DeleteAuthCodeEntry(ctx context.Context, keyer AuthCodeKeyer) error {
	return acm.locker.WithLock(keyer, func(lach *LockedAuthCodeHolder) error {
		return lach.Manager(acm.storage).DeleteAuthCodeEntry(ctx)
	})
}

func (acm *AuthCodeManager) DeleteDeviceAuthEntry(ctx context.Context, keyer AuthCodeKeyer) error {
	return acm.locker.WithLock(keyer, func(lach *LockedAuthCodeHolder) error {
		return lach.Manager(acm.storage).DeleteDeviceAuthEntry(ctx)
	})
}

func (acm *AuthCodeManager) ForEachAuthCodeKey(ctx context.Context, fn func(AuthCodeKeyer) error) error {
	view := logical.NewStorageView(acm.storage, authCodeKeyPrefix)
	return vaultext.ScanView(ctx, view, func(path string) error { return fn(AuthCodeKey(path)) })
}

func (acm *AuthCodeManager) ForEachDeviceAuthKey(ctx context.Context, fn func(AuthCodeKeyer) error) error {
	view := logical.NewStorageView(acm.storage, deviceAuthKeyPrefix)
	return vaultext.ScanView(ctx, view, func(path string) error { return fn(AuthCodeKey(path)) })
}

type AuthCodeHolder struct {
	locks []*locksutil.LockEntry
}

func (ach *AuthCodeHolder) WithLock(keyer AuthCodeKeyer, fn func(*LockedAuthCodeHolder) error) error {
	lock := locksutil.LockForKey(ach.locks, keyer.AuthCodeKey())
	lock.Lock()
	defer lock.Unlock()

	return fn(&LockedAuthCodeHolder{
		keyer: keyer,
	})
}

func (ach *AuthCodeHolder) Manager(storage logical.Storage) *AuthCodeManager {
	return &AuthCodeManager{
		storage: storage,
		locker:  ach,
	}
}
