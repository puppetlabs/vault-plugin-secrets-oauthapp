package provider

import (
	"errors"
	"fmt"
)

var (
	ErrNoSuchProvider        = errors.New("no provider with the given name")
	ErrNoProviderWithVersion = errors.New("version not supported")
	ErrNoOptions             = errors.New("options provided but none accepted")
)

type OptionError struct {
	Option  string
	Message string
	Cause   error
}

func (oe *OptionError) Error() string {
	msg := fmt.Sprintf("option %q: %s", oe.Option, oe.Message)
	if oe.Cause != nil {
		msg += ": " + oe.Cause.Error()
	}
	return msg
}

func (oe *OptionError) Unwrap() error {
	return oe.Cause
}
