package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/devicecode"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/semerr"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
	"golang.org/x/oauth2"
)

type MockClient struct {
	ID     string
	Secret string
}

func MockErrorResponse(statusCode int, obj interface{}) *oauth2.RetrieveError {
	re := &oauth2.RetrieveError{
		Response: &http.Response{
			StatusCode: statusCode,
			Status:     http.StatusText(statusCode),
		},
	}

	if obj != nil {
		body, err := json.Marshal(obj)
		if err != nil {
			panic(fmt.Errorf("failed to serialize mock error response body: %w", err))
		}

		re.Body = body
	}

	return re
}

type MockAuthCodeExchangeFunc func(code string, opts *provider.AuthCodeExchangeOptions) (*provider.Token, error)
type MockClientCredentialsFunc func(opts *provider.ClientCredentialsOptions) (*provider.Token, error)
type MockDeviceCodeAuthFunc func(opts *provider.DeviceCodeAuthOptions) (*devicecode.Auth, error)
type MockDeviceCodeExchangeFunc func(deviceCode string, opts *provider.DeviceCodeExchangeOptions) (*provider.Token, error)

type mockOperations struct {
	clientID             string
	owner                *mock
	authCodeExchangeFn   MockAuthCodeExchangeFunc
	clientCredentialsFn  MockClientCredentialsFunc
	deviceCodeAuthFn     MockDeviceCodeAuthFunc
	deviceCodeExchangeFn MockDeviceCodeExchangeFunc
}

func (mo *mockOperations) AuthCodeURL(state string, opts ...provider.AuthCodeURLOption) (string, bool) {
	o := &provider.AuthCodeURLOptions{}
	o.ApplyOptions(opts)

	return (&oauth2.Config{
		ClientID:    mo.clientID,
		Endpoint:    MockEndpoint.Endpoint,
		Scopes:      o.Scopes,
		RedirectURL: o.RedirectURL,
	}).AuthCodeURL(state, o.AuthCodeOptions...), true
}

func (mo *mockOperations) DeviceCodeAuth(ctx context.Context, opts ...provider.DeviceCodeAuthOption) (*devicecode.Auth, bool, error) {
	if mo.deviceCodeAuthFn == nil {
		return nil, false, nil
	}

	o := &provider.DeviceCodeAuthOptions{}
	o.ApplyOptions(opts)

	auth, err := mo.deviceCodeAuthFn(o)
	if err != nil {
		return nil, false, semerr.Map(err)
	}

	return auth, true, nil
}

func (mo *mockOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...provider.DeviceCodeExchangeOption) (*provider.Token, error) {
	if mo.deviceCodeExchangeFn == nil {
		return nil, semerr.Map(MockErrorResponse(http.StatusInternalServerError, nil))
	}

	o := &provider.DeviceCodeExchangeOptions{}
	o.ApplyOptions(opts)

	tok, err := mo.deviceCodeExchangeFn(deviceCode, o)
	if err != nil {
		// TODO: Would be nice to eliminate this duplication with basic.go.
		err = semerr.Map(err)
		err = errmark.MarkUserIf(
			err,
			errmark.RuleAny(
				semerr.RuleCode("access_denied"),
				semerr.RuleCode("expired_token"),
			),
		)

		return nil, err
	}

	tok.ProviderVersion = mo.owner.vsn
	tok.ProviderOptions = o.ProviderOptions

	return tok, nil
}

func (mo *mockOperations) AuthCodeExchange(ctx context.Context, code string, opts ...provider.AuthCodeExchangeOption) (*provider.Token, error) {
	if mo.authCodeExchangeFn == nil {
		return nil, semerr.Map(MockErrorResponse(http.StatusInternalServerError, nil))
	}

	o := &provider.AuthCodeExchangeOptions{}
	o.ApplyOptions(opts)

	tok, err := mo.authCodeExchangeFn(code, o)
	if err != nil {
		return nil, semerr.Map(err)
	}

	if tok.RefreshToken != "" {
		mo.owner.putRefreshTokenCode(tok.RefreshToken, code)
	}

	tok.ProviderVersion = mo.owner.vsn
	tok.ProviderOptions = o.ProviderOptions

	return tok, nil
}

func (mo *mockOperations) RefreshToken(ctx context.Context, t *provider.Token, opts ...provider.RefreshTokenOption) (*provider.Token, error) {
	if t.RefreshToken == "" || mo.authCodeExchangeFn == nil {
		return t, nil
	}

	code, ok := mo.owner.getRefreshTokenCode(t.RefreshToken)
	if !ok {
		return t, nil
	}

	o := &provider.RefreshTokenOptions{}
	provider.WithProviderOptions(t.ProviderOptions).ApplyToRefreshTokenOptions(o)
	o.ApplyOptions(opts)

	// TODO: It feels wrong to map one option type to another like this.
	tok, err := mo.authCodeExchangeFn(code, &provider.AuthCodeExchangeOptions{
		ProviderOptions: o.ProviderOptions,
	})
	if err != nil {
		return nil, semerr.Map(err)
	}

	if tok.RefreshToken != "" {
		mo.owner.putRefreshTokenCode(tok.RefreshToken, code)
	}

	tok.ProviderVersion = mo.owner.vsn
	tok.ProviderOptions = o.ProviderOptions

	return tok, nil
}

func (mo *mockOperations) ClientCredentials(ctx context.Context, opts ...provider.ClientCredentialsOption) (*provider.Token, error) {
	if mo.clientCredentialsFn == nil {
		return nil, semerr.Map(MockErrorResponse(http.StatusInternalServerError, nil))
	}

	o := &provider.ClientCredentialsOptions{}
	o.ApplyOptions(opts)

	tok, err := mo.clientCredentialsFn(o)
	if err != nil {
		return nil, semerr.Map(err)
	}

	tok.ProviderVersion = mo.owner.vsn
	tok.ProviderOptions = o.ProviderOptions

	return tok, nil
}

type mockProvider struct {
	owner *mock
}

func (mp *mockProvider) Version() int {
	return mp.owner.vsn
}

func (mp *mockProvider) Public(clientID string) provider.PublicOperations {
	return mp.Private(clientID, "")
}

func (mp *mockProvider) Private(clientID, clientSecret string) provider.PrivateOperations {
	mc := MockClient{ID: clientID, Secret: clientSecret}

	return &mockOperations{
		clientID:             clientID,
		authCodeExchangeFn:   mp.owner.authCodeExchangeFns[mc],
		clientCredentialsFn:  mp.owner.clientCredentialsFns[mc],
		deviceCodeAuthFn:     mp.owner.deviceCodeAuthFns[mc],
		deviceCodeExchangeFn: mp.owner.deviceCodeExchangeFns[mc],
		owner:                mp.owner,
	}
}

type mock struct {
	vsn                   int
	expectedOpts          map[string]string
	authCodeExchangeFns   map[MockClient]MockAuthCodeExchangeFunc
	clientCredentialsFns  map[MockClient]MockClientCredentialsFunc
	deviceCodeAuthFns     map[MockClient]MockDeviceCodeAuthFunc
	deviceCodeExchangeFns map[MockClient]MockDeviceCodeExchangeFunc
	refresh               map[string]string
	refreshMut            sync.RWMutex
}

func (m *mock) factory(ctx context.Context, vsn int, options map[string]string) (provider.Provider, error) {
	switch vsn {
	case -1, m.vsn:
	default:
		return nil, provider.ErrNoProviderWithVersion
	}

	for k, ev := range m.expectedOpts {
		av, found := options[k]
		if !found {
			return nil, &provider.OptionError{Option: k, Cause: fmt.Errorf("not found")}
		}

		if av != ev {
			return nil, &provider.OptionError{Option: k, Cause: fmt.Errorf("expected %q, got %q", ev, av)}
		}

		delete(options, k)
	}

	for k := range options {
		return nil, &provider.OptionError{Option: k, Cause: fmt.Errorf("unexpected")}
	}

	p := &mockProvider{
		owner: m,
	}
	return p, nil
}

func (m *mock) putRefreshTokenCode(refreshToken, code string) {
	m.refreshMut.Lock()
	defer m.refreshMut.Unlock()

	m.refresh[refreshToken] = code
}

func (m *mock) getRefreshTokenCode(refreshToken string) (string, bool) {
	m.refreshMut.RLock()
	defer m.refreshMut.RUnlock()

	code, found := m.refresh[refreshToken]
	return code, found
}

type MockOption func(m *mock)

func MockWithVersion(vsn int) MockOption {
	return func(m *mock) {
		m.vsn = vsn
	}
}

func MockWithExpectedOptionValue(opt, value string) MockOption {
	return func(m *mock) {
		m.expectedOpts[opt] = value
	}
}

func MockWithAuthCodeExchange(client MockClient, fn MockAuthCodeExchangeFunc) MockOption {
	return func(m *mock) {
		m.authCodeExchangeFns[client] = fn
	}
}

func MockWithClientCredentials(client MockClient, fn MockClientCredentialsFunc) MockOption {
	return func(m *mock) {
		m.clientCredentialsFns[client] = fn
	}
}

func MockWithDeviceCodeAuth(client MockClient, fn MockDeviceCodeAuthFunc) MockOption {
	return func(m *mock) {
		m.deviceCodeAuthFns[client] = fn
	}
}

func MockWithDeviceCodeExchange(client MockClient, fn MockDeviceCodeExchangeFunc) MockOption {
	return func(m *mock) {
		m.deviceCodeExchangeFns[client] = fn
	}
}

func MockFactory(opts ...MockOption) provider.FactoryFunc {
	m := &mock{
		expectedOpts:          make(map[string]string),
		authCodeExchangeFns:   make(map[MockClient]MockAuthCodeExchangeFunc),
		clientCredentialsFns:  make(map[MockClient]MockClientCredentialsFunc),
		deviceCodeAuthFns:     make(map[MockClient]MockDeviceCodeAuthFunc),
		deviceCodeExchangeFns: make(map[MockClient]MockDeviceCodeExchangeFunc),
		refresh:               make(map[string]string),
	}

	MockWithVersion(1)(m)
	for _, opt := range opts {
		opt(m)
	}

	return m.factory
}
