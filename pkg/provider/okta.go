package provider

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/devicecode"
)

const (
	OptionDomain     = "domain"
	OptionPrivateKey = "private_key"
	OptionScheme     = "scheme"
	OktaProviderV1   = 1

	JWTExpirationTime = time.Hour
)

func init() {
	GlobalRegistry.MustRegister("okta", OktaFactory)
}

type oktaToken struct {
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

type oktaOperations struct {
	vsn             int
	endpointFactory EndpointFactoryFunc
	clientID        string
	clientSecret    string
	privateKey      *rsa.PrivateKey
	usePrivateKey   bool
	httpClient      *http.Client
}

func (o *oktaOperations) createClientAssertion() (string, error) {
	if !o.usePrivateKey || o.privateKey == nil {
		return "", fmt.Errorf("private key not configured")
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: o.privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    o.clientID,
		Subject:   o.clientID,
		Audience:  jwt.Audience{o.endpointFactory(nil).TokenURL},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(JWTExpirationTime)),
		ID:        uuid.New().String(),
	}

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to create JWT: %w", err)
	}

	return token, nil
}

func (o *oktaOperations) ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error) {
	options := &ClientCredentialsOptions{}
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)

	if o.usePrivateKey {
		// Private Key JWT - Direct HTTP request
		clientAssertion, err := o.createClientAssertion()
		if err != nil {
			return nil, fmt.Errorf("failed to create client assertion: %w", err)
		}

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("scope", strings.Join(options.Scopes, " "))
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Set("client_assertion", clientAssertion)

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint.TokenURL, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, err := o.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			var errResp struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			if err := json.Unmarshal(body, &errResp); err == nil {
				return nil, fmt.Errorf("authentication failed: %s, %s", errResp.Error, errResp.ErrorDescription)
			}
			return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var oktaToken oktaToken
		if err := json.Unmarshal(body, &oktaToken); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		token := &oauth2.Token{
			AccessToken: oktaToken.AccessToken,
			TokenType:   oktaToken.TokenType,
			Expiry:      time.Now().Add(time.Duration(oktaToken.ExpiresIn) * time.Second),
		}

		return &Token{
			Token:           token,
			ProviderVersion: o.vsn,
			ProviderOptions: options.ProviderOptions,
		}, nil
	}

	// Client Secret - Use clientcredentials package
	if o.clientSecret == "" {
		return nil, errmark.MarkUser(ErrMissingClientSecret)
	}

	cc := &clientcredentials.Config{
		ClientID:       o.clientID,
		ClientSecret:   o.clientSecret,
		TokenURL:       endpoint.TokenURL,
		Scopes:         options.Scopes,
		EndpointParams: options.EndpointParams,
		AuthStyle:      endpoint.AuthStyle,
	}

	tok, err := cc.Token(ctx)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:           tok,
		ProviderVersion: o.vsn,
		ProviderOptions: options.ProviderOptions,
	}, nil
}

func (o *oktaOperations) AuthCodeURL(state string, opts ...AuthCodeURLOption) (string, bool) {
	options := &AuthCodeURLOptions{}
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)
	if endpoint.AuthURL == "" {
		return "", false
	}

	cfg := &oauth2.Config{
		Endpoint:    endpoint.Endpoint,
		ClientID:    o.clientID,
		Scopes:      options.Scopes,
		RedirectURL: options.RedirectURL,
	}

	return cfg.AuthCodeURL(state, options.AuthCodeOptions...), true
}

func (o *oktaOperations) DeviceCodeAuth(ctx context.Context, opts ...DeviceCodeAuthOption) (*devicecode.Auth, bool, error) {
	return nil, false, nil
}

func (o *oktaOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...DeviceCodeExchangeOption) (*Token, error) {
	return nil, fmt.Errorf("device code flow not supported")
}

func (o *oktaOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	return nil, fmt.Errorf("auth code exchange flow not supported")
}

func (o *oktaOperations) TokenExchange(ctx context.Context, t *Token, opts ...TokenExchangeOption) (*Token, error) {
	return nil, fmt.Errorf("token exchange flow not supported")
}

func (o *oktaOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	options := &RefreshTokenOptions{}
	WithProviderOptions(t.ProviderOptions).ApplyToRefreshTokenOptions(options)
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)

	cfg := &oauth2.Config{
		Endpoint:     endpoint.Endpoint,
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
	}

	tok, err := cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: t.RefreshToken,
	}).Token()
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:           tok,
		ProviderVersion: o.vsn,
		ProviderOptions: options.ProviderOptions,
	}, nil
}

type okta struct {
	vsn             int
	endpointFactory EndpointFactoryFunc
	privateKey      *rsa.PrivateKey
	usePrivateKey   bool
}

func (o *okta) Version() int {
	return o.vsn
}

func (o *okta) Public(clientID string) PublicOperations {
	return o.Private(clientID, "")
}

func (o *okta) Private(clientID, clientSecret string) PrivateOperations {
	return &oktaOperations{
		vsn:             o.vsn,
		endpointFactory: o.endpointFactory,
		clientID:        clientID,
		clientSecret:    clientSecret,
		privateKey:      o.privateKey,
		usePrivateKey:   o.usePrivateKey,
		httpClient:      &http.Client{},
	}
}

func OktaFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, OktaProviderV1)

	switch vsn {
	case OktaProviderV1:
	default:
		return nil, ErrNoProviderWithVersion
	}

	domain := opts[OptionDomain]
	if domain == "" {
		return nil, &OptionError{Option: OptionDomain, Cause: fmt.Errorf("domain is required")}
	}

	var privateKey *rsa.PrivateKey
	usePrivateKey := false

	if keyPEM := opts[OptionPrivateKey]; keyPEM != "" {
		block, _ := pem.Decode([]byte(keyPEM))
		if block == nil {
			return nil, &OptionError{Option: OptionPrivateKey, Cause: fmt.Errorf("failed to parse PEM block")}
		}

		// Only support PKCS8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, &OptionError{Option: OptionPrivateKey, Cause: fmt.Errorf("failed to parse PKCS8 private key: %w", err)}
		}

		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, &OptionError{Option: OptionPrivateKey, Cause: fmt.Errorf("key is not an RSA private key")}
		}

		usePrivateKey = true
	}

	scheme := opts[OptionScheme]
	if scheme == "" {
		scheme = "https"
	}

	p := &okta{
		vsn: vsn,
		endpointFactory: StaticEndpointFactory(Endpoint{
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("%s://%s/oauth2/v1/authorize", scheme, domain),
				TokenURL: fmt.Sprintf("%s://%s/oauth2/v1/token", scheme, domain),
			},
		}),
		privateKey:    privateKey,
		usePrivateKey: usePrivateKey,
	}

	return p, nil
}
