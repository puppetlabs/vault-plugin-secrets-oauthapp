package provider

import (
	"context"

	"golang.org/x/oauth2/google"
)

func init() {
	GlobalRegistry.MustRegister("google", GoogleFactory)
}

func GoogleFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 2)

	switch vsn {
	case 2:
		fields, err := parseOIDCExtraDataFields(opts["extra_data_fields"])
		if err != nil {
			return nil, &OptionError{Option: "extra_data_fields", Cause: err}
		}

		return newOIDC(ctx, vsn, "https://accounts.google.com", fields) // https://developers.google.com/identity/protocols/oauth2/openid-connect#discovery
	case 1:
		if len(opts) != 0 {
			return nil, ErrNoOptions
		}

		return &basic{
			vsn: vsn,
			endpoint: Endpoint{
				Endpoint:  google.Endpoint,
				DeviceURL: "https://oauth2.googleapis.com/device/code", // https://developers.google.com/identity/protocols/oauth2/limited-input-device#step-1:-request-device-and-user-codes
			},
		}, nil
	default:
		return nil, ErrNoProviderWithVersion
	}
}
