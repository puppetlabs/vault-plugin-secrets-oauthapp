package provider

import (
	"net/url"

	"golang.org/x/oauth2"
)

type WithRedirectURL string

var _ AuthCodeURLOption = WithRedirectURL("")
var _ AuthCodeExchangeOption = WithRedirectURL("")

func (wru WithRedirectURL) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	target.RedirectURL = string(wru)
}

func (wru WithRedirectURL) ApplyToAuthCodeExchangeOptions(target *AuthCodeExchangeOptions) {
	target.RedirectURL = string(wru)
}

type WithScopes []string

var _ AuthCodeURLOption = WithScopes(nil)
var _ DeviceCodeAuthOption = WithScopes(nil)
var _ ClientCredentialsOption = WithScopes(nil)

func (ws WithScopes) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	target.Scopes = append(target.Scopes, ws...)
}

func (ws WithScopes) ApplyToDeviceCodeAuthOptions(target *DeviceCodeAuthOptions) {
	target.Scopes = append(target.Scopes, ws...)
}

func (ws WithScopes) ApplyToClientCredentialsOptions(target *ClientCredentialsOptions) {
	target.Scopes = append(target.Scopes, ws...)
}

type WithURLParams map[string]string

var _ AuthCodeURLOption = WithURLParams(nil)
var _ AuthCodeExchangeOption = WithURLParams(nil)
var _ ClientCredentialsOption = WithURLParams(nil)

func (wup WithURLParams) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	for k, v := range wup {
		target.AuthCodeOptions = append(target.AuthCodeOptions, oauth2.SetAuthURLParam(k, v))
	}
}

func (wup WithURLParams) ApplyToAuthCodeExchangeOptions(target *AuthCodeExchangeOptions) {
	for k, v := range wup {
		target.AuthCodeOptions = append(target.AuthCodeOptions, oauth2.SetAuthURLParam(k, v))
	}
}

func (wup WithURLParams) ApplyToClientCredentialsOptions(target *ClientCredentialsOptions) {
	if target.EndpointParams == nil {
		target.EndpointParams = make(url.Values, len(wup))
	}

	for k, v := range wup {
		target.EndpointParams.Set(k, v)
	}
}

type WithProviderOptions map[string]string

var _ AuthCodeURLOption = WithProviderOptions(nil)
var _ DeviceCodeAuthOption = WithProviderOptions(nil)
var _ DeviceCodeExchangeOption = WithProviderOptions(nil)
var _ AuthCodeExchangeOption = WithProviderOptions(nil)
var _ RefreshTokenOption = WithProviderOptions(nil)
var _ ClientCredentialsOption = WithProviderOptions(nil)

func (wpo WithProviderOptions) ApplyToAuthCodeURLOptions(target *AuthCodeURLOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToDeviceCodeAuthOptions(target *DeviceCodeAuthOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToDeviceCodeExchangeOptions(target *DeviceCodeExchangeOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToAuthCodeExchangeOptions(target *AuthCodeExchangeOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToRefreshTokenOptions(target *RefreshTokenOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}

func (wpo WithProviderOptions) ApplyToClientCredentialsOptions(target *ClientCredentialsOptions) {
	if target.ProviderOptions == nil {
		target.ProviderOptions = make(map[string]string, len(wpo))
	}

	for k, v := range wpo {
		target.ProviderOptions[k] = v
	}
}
