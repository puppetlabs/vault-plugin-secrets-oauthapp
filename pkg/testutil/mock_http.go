package testutil

import (
	"net/http"
	"net/http/httptest"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/provider"
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
	ch := make(chan struct{})
	w := httptest.NewRecorder()
	go func() {
		defer close(ch)
		mrt.Handler.ServeHTTP(w, r)
	}()
	select {
	case <-ch:
		return w.Result(), nil
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
}

var MockEndpoint = provider.Endpoint{
	Endpoint: oauth2.Endpoint{
		AuthURL:  MockAuthCodeURL,
		TokenURL: MockTokenURL,
	},
	DeviceURL: MockDeviceCodeURL,
}
