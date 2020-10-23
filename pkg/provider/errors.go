package provider

import (
	"errors"
	"fmt"
)

var (
	ErrNoSuchProvider        = errors.New("provider: no provider with the given name")
	ErrNoProviderWithVersion = errors.New("provider: version not supported")
	ErrNoOptions             = errors.New("provider: options provided but none accepted")
	ErrAuthRequired          = errors.New("provider: authorization is required")
)

type OptionError struct {
	Option  string
	Message string
}

func (oe *OptionError) Error() string {
	return fmt.Sprintf("provider: option %q: %s", oe.Option, oe.Message)
}
