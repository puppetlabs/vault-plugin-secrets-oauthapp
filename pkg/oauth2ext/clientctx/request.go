package clientctx

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

type roundTripper struct {
	http.RoundTripper
	fn func(req *http.Request) error
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if err := t.fn(req); err != nil {
		return nil, err
	}
	return t.RoundTripper.RoundTrip(req)
}

// WithUpdatedRequest returns a context that wraps the current OAuth2 HTTP
// client with a function that can amend a request in flight.
//
// The API provided by the OAuth2 package is not sufficient for some
// applications. For example, the OAuth2 package does not provide a way to
// specify multiple audiences or resources for a request per RFC 8693.
func WithUpdatedRequest(ctx context.Context, fn func(req *http.Request) error) context.Context {
	orig := oauth2.NewClient(ctx, nil)

	transport := orig.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	upd := &http.Client{}
	*upd = *orig
	upd.Transport = &roundTripper{
		RoundTripper: transport,
		fn:           fn,
	}

	return context.WithValue(ctx, oauth2.HTTPClient, upd)
}

// WithUpdatedRequestBody returns a context that wraps the current OAuth2 HTTP
// client with a function that can amend the body of a request in flight.
func WithUpdatedRequestBody(ctx context.Context, fn func(body []byte) ([]byte, error)) context.Context {
	return WithUpdatedRequest(ctx, func(req *http.Request) (err error) {
		closed := false
		closer := req.Body
		defer func() {
			if closed {
				return
			}
			if cerr := closer.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}()
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		closed = true
		if err := closer.Close(); err != nil {
			return err
		}

		body, err = fn(body)
		if err != nil {
			return err
		}

		req.ContentLength = int64(len(body))
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		return nil
	})
}
