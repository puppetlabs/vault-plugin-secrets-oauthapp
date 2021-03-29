package testutil

import (
	"net/http"
	"net/http/httptest"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
	"golang.org/x/oauth2"
)

/* #nosec G101 */
const (
	MockAuthCodeURL   = "http://localhost/authorize"
	MockDeviceCodeURL = "http://localhost/device"
	MockTokenURL      = "http://localhost/token"
)

type MockRoundTripper struct {
	Handler http.Handler
}

func (mrt *MockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	mrt.Handler.ServeHTTP(w, r)
	return w.Result(), nil
}

var MockEndpoint = provider.Endpoint{
	Endpoint: oauth2.Endpoint{
		AuthURL:  MockAuthCodeURL,
		TokenURL: MockTokenURL,
	},
	DeviceURL: MockDeviceCodeURL,
}
