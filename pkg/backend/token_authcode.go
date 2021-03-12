package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/scheduler"
)

type refreshProcess struct {
	backend *backend
	storage logical.Storage
	key     string
}

var _ scheduler.Process = &refreshProcess{}

func (rp *refreshProcess) Description() string {
	return fmt.Sprintf("credential refresh (%s)", rp.key)
}

func (rp *refreshProcess) Run(ctx context.Context) error {
	_, err := rp.backend.getRefreshCredToken(ctx, rp.storage, rp.key, nil)
	return err
}

type refreshDescriptor struct {
	backend *backend
	storage logical.Storage
}

var _ scheduler.Descriptor = &refreshDescriptor{}

func (rd *refreshDescriptor) Run(ctx context.Context, pc chan<- scheduler.Process) error {
	view := logical.NewStorageView(rd.storage, credsPathPrefix)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		err := logical.ScanView(ctx, view, func(path string) {
			proc := &refreshProcess{
				backend: rd.backend,
				storage: rd.storage,
				key:     view.ExpandKey(path),
			}

			select {
			case pc <- proc:
			case <-ctx.Done():
			}
		})
		if err != nil {
			return err
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil
		}
	}
}

func (b *backend) refreshCredToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*credToken, error) {
	lock := locksutil.LockForKey(b.locks, key)
	lock.Lock()
	defer lock.Unlock()

	// In case someone else refreshed this token from under us, we'll re-request
	// it here with the lock acquired.
	tok, err := getCredTokenLocked(ctx, storage, key)
	switch {
	case err != nil:
		return nil, err
	case tok == nil:
		return nil, nil
	case !tok.Issued() || tokenValid(tok.Token, data) || tok.RefreshToken == "":
		return tok, nil
	}

	c, err := b.getCache(ctx, storage)
	if err != nil {
		return nil, err
	} else if c == nil {
		return nil, ErrNotConfigured
	}

	// Refresh.
	refreshed, err := c.Provider.Private(c.Config.ClientID, c.Config.ClientSecret).RefreshToken(ctx, tok.Token)
	if err != nil {
		tok.LastAttemptedIssueTime = time.Now()

		msg := errmap.Wrap(errmark.MarkShort(err), "refresh failed").Error()
		if errmark.MarkedUser(err) {
			tok.UserError = msg
		} else {
			tok.TransientErrorsSinceLastIssue++
			tok.LastTransientError = msg
		}
	} else {
		tok.Token = refreshed
		tok.LastIssueTime = time.Now()
		tok.UserError = ""
		tok.TransientErrorsSinceLastIssue = 0
		tok.LastTransientError = ""
		tok.LastAttemptedIssueTime = time.Time{}
	}

	// Store the new token.
	entry, err := logical.StorageEntryJSON(key, tok)
	if err != nil {
		return nil, err
	}

	if err := storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return tok, nil
}

func (b *backend) getRefreshCredToken(ctx context.Context, storage logical.Storage, key string, data *framework.FieldData) (*credToken, error) {
	tok, err := b.getCredToken(ctx, storage, key)
	switch {
	case err != nil:
		return nil, err
	case tok == nil:
		return nil, nil
	case !tok.Issued() || tokenValid(tok.Token, data):
		return tok, nil
	default:
		return b.refreshCredToken(ctx, storage, key, data)
	}
}
