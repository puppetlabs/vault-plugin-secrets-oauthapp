package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

type credToken struct {
	// We embed a *provider.Token as the base type. This ensures compatibility
	// and keeps storage size reasonable because this will be the default
	// configuration.
	*provider.Token `json:",inline"`

	// LastIssueTime is the most recent time a token was successfully issued.
	LastIssueTime time.Time `json:"last_issue_time,omitempty"`

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

// Issued indicates whether a token has been issued at all.
//
// For certain grant types, like device code flow, we may not have an access
// token yet. In that case, we must wait for a polling process to update this
// value. A temporary error will be returned.
func (ct *credToken) Issued() bool {
	return ct.Token != nil && ct.AccessToken != ""
}

func getCredTokenLocked(ctx context.Context, storage logical.Storage, key string) (*credToken, error) {
	entry, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	}

	tok := &credToken{}
	if err := entry.DecodeJSON(tok); err != nil {
		return nil, err
	}

	return tok, nil
}

func (b *backend) getCredToken(ctx context.Context, storage logical.Storage, key string) (*credToken, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.RLock()
	defer lock.RUnlock()

	return getCredTokenLocked(ctx, storage, key)
}
