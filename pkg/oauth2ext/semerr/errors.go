package semerr

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/oauth2ext/interop"
	"golang.org/x/oauth2"
)

type Error struct {
	Code        string
	Description string
	URI         string
}

func (e *Error) Error() string {
	msg := "server rejected request: " + e.Code
	if e.Description != "" {
		msg += ": " + e.Description
	}
	if e.URI != "" {
		msg += " (see " + e.URI + ")"
	}
	return msg
}

func IsCode(err error, code string) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}

	return e.Code == code
}

func RuleCode(code string) errmark.Rule {
	return errmark.RuleFunc(func(err error) bool {
		return IsCode(err, code)
	})
}

func Map(cerr error) error {
	if cerr == nil {
		return nil
	}

	// We consider any net.OpError to be temporary. E.g., a server might be down
	// and we need to try a refresh again later.
	var nerr *net.OpError
	if errors.As(cerr, &nerr) {
		return errmark.MarkTransient(cerr)
	}

	rerr, ok := cerr.(*oauth2.RetrieveError)
	if !ok {
		return cerr
	}

	switch rerr.Response.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
	default:
		return rerr
	}

	var env interop.JSONError
	if json.Unmarshal(rerr.Body, &env) != nil {
		return rerr
	}

	return errmark.MarkUserIf(
		&Error{
			Code:        env.Error,
			Description: env.ErrorDescription,
			URI:         env.ErrorURI,
		},
		errmark.RuleAny(
			RuleCode("invalid_request"),
			RuleCode("invalid_client"),
			RuleCode("invalid_grant"),
			RuleCode("unauthorized_client"),
			RuleCode("unsupported_grant_type"),
			RuleCode("invalid_scope"),
		),
	)
}
