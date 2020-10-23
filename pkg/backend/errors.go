package backend

import "errors"

var (
	ErrNotConfigured      = errors.New("not configured")
	ErrInvalidCredentials = errors.New("invalid client credentials")
)
