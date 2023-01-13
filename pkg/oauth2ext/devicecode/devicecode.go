package devicecode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/interop"
	"golang.org/x/oauth2"
)

const (
	GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

type Auth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int32  `json:"expires_in"`
	Interval                int32  `json:"interval,omitempty"`
}

type Config struct {
	*oauth2.Config

	DeviceURL string
}

func (c *Config) DeviceCodeAuth(ctx context.Context) (*Auth, error) {
	v := url.Values{
		"client_id": {c.ClientID},
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.DeviceURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := oauth2.NewClient(ctx, nil).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// This is the same restriction as used by Go's OAuth2 package for
	// consistency.
	reader := io.LimitReader(resp.Body, 1<<20)

	switch {
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch device code authorization: %w", err)
		}

		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
	default:
		auth := &Auth{}
		if err := json.NewDecoder(reader).Decode(auth); err != nil {
			return nil, err
		}
		switch {
		case auth.DeviceCode == "":
			return nil, errors.New("server response missing device_code")
		case auth.UserCode == "":
			return nil, errors.New("server response missing user_code")
		case auth.VerificationURI == "":
			return nil, errors.New("server response missing verification_uri")
		case auth.ExpiresIn <= 0:
			return nil, errors.New("server response missing expires_in")
		}

		return auth, nil
	}
}

func (c *Config) DeviceCodeExchange(ctx context.Context, deviceCode string) (*oauth2.Token, error) {
	v := url.Values{
		"grant_type":  {GrantType},
		"client_id":   {c.ClientID},
		"device_code": {deviceCode},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := oauth2.NewClient(ctx, nil).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// This is the same restriction as used by Go's OAuth2 package for
	// consistency.
	reader := io.LimitReader(resp.Body, 1<<20)

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch device code authorization: %w", err)
	}

	switch {
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
	default:
		var base interop.JSONToken
		if err := json.Unmarshal(body, &base); err != nil {
			return nil, err
		}
		if base.AccessToken == "" {
			return nil, errors.New("server response missing access_token")
		}

		tok := &oauth2.Token{
			AccessToken:  base.AccessToken,
			TokenType:    base.TokenType,
			RefreshToken: base.RefreshToken,
		}
		if base.ExpiresIn != 0 {
			tok.Expiry = time.Now().Add(time.Duration(base.ExpiresIn) * time.Second)
		}

		// The Go library does not check for errors here. If there is one, it
		// will be ignored.
		var extra map[string]interface{}
		_ = json.Unmarshal(body, &extra)

		if extra != nil {
			tok = tok.WithExtra(extra)
		}

		return tok, nil
	}
}
