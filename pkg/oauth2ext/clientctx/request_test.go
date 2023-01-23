package clientctx_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/clientctx"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestWithUpdatedRequest(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, err := io.Copy(w, r.Body)
		require.NoError(t, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, srv.Client())
	ctx = clientctx.WithUpdatedRequestBody(ctx, func(body []byte) ([]byte, error) {
		return bytes.Join([][]byte{body, []byte("amended")}, []byte("+")), nil
	})

	client := oauth2.NewClient(ctx, nil)
	resp, err := client.Post(srv.URL, "text/plain", strings.NewReader("original"))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("original+amended"), body)
}
