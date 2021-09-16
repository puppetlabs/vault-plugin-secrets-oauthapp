package backend

import (
	"errors"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
)

var (
	ErrMissingServerField = errors.New("missing server (consider configuring a default server)")
	ErrNoSuchServer       = errors.New("server configuration does not exist (was it deleted?)")
)

func errorResponse(err error) (*logical.Response, error) {
	if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmark.MarkShort(err).Error()), nil
	}

	return nil, err
}
