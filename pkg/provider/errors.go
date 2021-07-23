package provider

import (
	"errors"
	"fmt"
)

var (
	ErrNoSuchProvider        = errors.New("no provider with the given name")
	ErrNoProviderWithVersion = errors.New("version not supported")
	ErrNoOptions             = errors.New("options provided but none accepted")
	ErrMissingClientSecret   = errors.New("missing client secret in configuration")
)

type OptionError struct {
	Option string
	Cause  error
}

func (oe *OptionError) Error() string {
	return fmt.Sprintf("option %q: %s", oe.Option, oe.Cause)
}

func (oe *OptionError) Unwrap() error {
	return oe.Cause
}
