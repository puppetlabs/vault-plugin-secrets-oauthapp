package backend

import "errors"

var (
	ErrNoSuchServer = errors.New("no server with the given name")
)
