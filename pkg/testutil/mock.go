package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"golang.org/x/oauth2"
)

/* #nosec G101 */
const (
	MockAuthCodeURL = "http://localhost/authorize"
	MockTokenURL    = "http://localhost/token"
)

type MockRoundTripper struct {
	Handler http.Handler
}

func (mrt *MockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	mrt.Handler.ServeHTTP(w, r)
	return w.Result(), nil
}

var MockEndpoint = oauth2.Endpoint{
	AuthURL:  MockAuthCodeURL,
	TokenURL: MockTokenURL,
}

type MockClient struct {
	ID     string
	Secret string
}

type MockAuthCodeExchangeFunc func(code string, opts *provider.AuthCodeExchangeOptions) (*provider.Token, error)
type MockClientCredentialsFunc func(opts *provider.ClientCredentialsOptions) (*provider.Token, error)

func StaticMockAuthCodeExchange(token *provider.Token) MockAuthCodeExchangeFunc {
	return func(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		return token, nil
	}
}

func StaticMockClientCredentials(token *provider.Token) MockClientCredentialsFunc {
	return func(_ *provider.ClientCredentialsOptions) (*provider.Token, error) {
		return token, nil
	}
}

func AmendTokenMockAuthCodeExchange(get MockAuthCodeExchangeFunc, amend func(token *provider.Token) error) MockAuthCodeExchangeFunc {
	return func(candidate string, opts *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		token, err := get(candidate, opts)
		if err != nil {
			return nil, err
		}

		if err := amend(token); err != nil {
			return nil, err
		}

		return token, nil
	}
}

func AmendTokenMockClientCredentials(get MockClientCredentialsFunc, amend func(token *provider.Token) error) MockClientCredentialsFunc {
	return func(opts *provider.ClientCredentialsOptions) (*provider.Token, error) {
		token, err := get(opts)
		if err != nil {
			return nil, err
		}

		if err := amend(token); err != nil {
			return nil, err
		}

		return token, nil
	}
}

func ExpiringMockAuthCodeExchange(fn MockAuthCodeExchangeFunc, duration time.Duration) MockAuthCodeExchangeFunc {
	return AmendTokenMockAuthCodeExchange(fn, func(t *provider.Token) error {
		t.Expiry = time.Now().Add(duration)
		return nil
	})
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}

func RefreshableMockAuthCodeExchange(fn MockAuthCodeExchangeFunc, step func(i int) (time.Duration, error)) MockAuthCodeExchangeFunc {
	refreshToken := randomToken(40)
	var i int32

	return AmendTokenMockAuthCodeExchange(fn, func(t *provider.Token) error {
		exp, err := step(int(atomic.AddInt32(&i, 1)))
		if err != nil {
			return err
		}

		t.RefreshToken = refreshToken
		t.Expiry = time.Now().Add(exp)
		return nil
	})
}

func RandomMockAuthCodeExchange(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
	t := &oauth2.Token{
		AccessToken: randomToken(10),
	}
	return &provider.Token{Token: t}, nil
}

func IncrementMockAuthCodeExchange(prefix string) MockAuthCodeExchangeFunc {
	var i int32

	return func(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		t := &oauth2.Token{
			AccessToken: fmt.Sprintf("%s%d", prefix, atomic.AddInt32(&i, 1)),
		}
		return &provider.Token{Token: t}, nil
	}
}

func IncrementMockClientCredentials(prefix string) MockClientCredentialsFunc {
	var i int32

	return func(_ *provider.ClientCredentialsOptions) (*provider.Token, error) {
		t := &oauth2.Token{
			AccessToken: fmt.Sprintf("%s%d", prefix, atomic.AddInt32(&i, 1)),
		}
		return &provider.Token{Token: t}, nil
	}
}

func ErrorMockAuthCodeExchange(_ string, _ *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
	return nil, &oauth2.RetrieveError{Response: &http.Response{Status: http.StatusText(http.StatusForbidden)}}
}

func RestrictMockAuthCodeExchange(m map[string]MockAuthCodeExchangeFunc) MockAuthCodeExchangeFunc {
	return func(token string, opts *provider.AuthCodeExchangeOptions) (*provider.Token, error) {
		fn, found := m[token]
		if !found {
			fn = ErrorMockAuthCodeExchange
		}

		return fn(token, opts)
	}
}

type mockOperations struct {
	clientID            string
	owner               *mock
	authCodeExchangeFn  MockAuthCodeExchangeFunc
	clientCredentialsFn MockClientCredentialsFunc
}

func (mo *mockOperations) AuthCodeURL(state string, opts ...provider.AuthCodeURLOption) (string, bool) {
	o := &provider.AuthCodeURLOptions{}
	o.ApplyOptions(opts)

	return (&oauth2.Config{
		ClientID:    mo.clientID,
		Endpoint:    MockEndpoint,
		Scopes:      o.Scopes,
		RedirectURL: o.RedirectURL,
	}).AuthCodeURL(state, o.AuthCodeOptions...), true
}

func (mo *mockOperations) AuthCodeExchange(ctx context.Context, code string, opts ...provider.AuthCodeExchangeOption) (*provider.Token, error) {
	if mo.authCodeExchangeFn == nil {
		return nil, &oauth2.RetrieveError{Response: &http.Response{Status: http.StatusText(http.StatusInternalServerError)}}
	}

	o := &provider.AuthCodeExchangeOptions{}
	o.ApplyOptions(opts)

	tok, err := mo.authCodeExchangeFn(code, o)
	if err != nil {
		return nil, err
	}

	if tok.RefreshToken != "" {
		mo.owner.putRefreshTokenCode(tok.RefreshToken, code)
	}

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
	o.ApplyOptions(opts)

	// TODO: It feels wrong to map one option type to another like this.
	return mo.authCodeExchangeFn(code, &provider.AuthCodeExchangeOptions{
		ProviderOptions: o.ProviderOptions,
	})
}

func (mo *mockOperations) ClientCredentials(ctx context.Context, opts ...provider.ClientCredentialsOption) (*provider.Token, error) {
	if mo.clientCredentialsFn == nil {
		return nil, &oauth2.RetrieveError{Response: &http.Response{Status: http.StatusText(http.StatusInternalServerError)}}
	}

	o := &provider.ClientCredentialsOptions{}
	o.ApplyOptions(opts)

	return mo.clientCredentialsFn(o)
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
		clientID:            clientID,
		authCodeExchangeFn:  mp.owner.authCodeExchangeFns[mc],
		clientCredentialsFn: mp.owner.clientCredentialsFns[mc],
		owner:               mp.owner,
	}
}

type mock struct {
	vsn                  int
	expectedOpts         map[string]string
	authCodeExchangeFns  map[MockClient]MockAuthCodeExchangeFunc
	clientCredentialsFns map[MockClient]MockClientCredentialsFunc
	refresh              map[string]string
	refreshMut           sync.RWMutex
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
			return nil, &provider.OptionError{Option: k, Message: "not found"}
		}

		if av != ev {
			return nil, &provider.OptionError{Option: k, Message: fmt.Sprintf("expected %q, got %q", ev, av)}
		}

		delete(options, k)
	}

	for k := range options {
		return nil, &provider.OptionError{Option: k, Message: "unexpected"}
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

func MockFactory(opts ...MockOption) provider.FactoryFunc {
	m := &mock{
		expectedOpts:         make(map[string]string),
		authCodeExchangeFns:  make(map[MockClient]MockAuthCodeExchangeFunc),
		clientCredentialsFns: make(map[MockClient]MockClientCredentialsFunc),
		refresh:              make(map[string]string),
	}

	MockWithVersion(1)(m)
	for _, opt := range opts {
		opt(m)
	}

	return m.factory
}
