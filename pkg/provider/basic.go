package provider

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/bitbucket"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/slack"
)

func init() {
	GlobalRegistry.MustRegister("bitbucket", basicFactory(bitbucket.Endpoint))
	GlobalRegistry.MustRegister("github", basicFactory(github.Endpoint))
	GlobalRegistry.MustRegister("gitlab", basicFactory(gitlab.Endpoint))
	GlobalRegistry.MustRegister("google", basicFactory(google.Endpoint))
	GlobalRegistry.MustRegister("microsoft_azure_ad", azureADFactory)
	GlobalRegistry.MustRegister("slack", basicFactory(slack.Endpoint))

	GlobalRegistry.MustRegister("custom", customFactory)
}

type basicAuthCodeURLConfigBuilder struct {
	config *oauth2.Config
}

func (cb *basicAuthCodeURLConfigBuilder) WithRedirectURL(redirectURL string) AuthCodeURLConfigBuilder {
	cb.config.RedirectURL = redirectURL
	return cb
}

func (cb *basicAuthCodeURLConfigBuilder) WithScopes(scopes ...string) AuthCodeURLConfigBuilder {
	cb.config.Scopes = scopes
	return cb
}

func (cb *basicAuthCodeURLConfigBuilder) Build() AuthCodeURLConfig {
	return cb.config
}

type basicExchangeConfig struct {
	config *oauth2.Config
	client *http.Client
}

func (c *basicExchangeConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if c.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.client)
	}

	return c.config.Exchange(ctx, code, opts...)
}

func (c *basicExchangeConfig) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	if c.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.client)
	}

	return c.config.TokenSource(ctx, t)
}

type basicExchangeConfigBuilder struct {
	config *oauth2.Config
	client *http.Client
}

func (cb *basicExchangeConfigBuilder) WithHTTPClient(client *http.Client) ExchangeConfigBuilder {
	cb.client = client
	return cb
}

func (cb *basicExchangeConfigBuilder) WithRedirectURL(redirectURL string) ExchangeConfigBuilder {
	cb.config.RedirectURL = redirectURL
	return cb
}

func (cb *basicExchangeConfigBuilder) Build() ExchangeConfig {
	return &basicExchangeConfig{
		config: cb.config,
		client: cb.client,
	}
}

type basic struct {
	vsn      int
	endpoint oauth2.Endpoint
}

func (b *basic) Version() int {
	return b.vsn
}

func (b *basic) NewAuthCodeURLConfigBuilder(clientID string) AuthCodeURLConfigBuilder {
	return &basicAuthCodeURLConfigBuilder{
		config: &oauth2.Config{
			ClientID: clientID,
			Endpoint: b.endpoint,
		},
	}
}

func (b *basic) NewExchangeConfigBuilder(clientID, clientSecret string) ExchangeConfigBuilder {
	return &basicExchangeConfigBuilder{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     b.endpoint,
		},
	}
}

func basicFactory(endpoint oauth2.Endpoint) FactoryFunc {
	return func(vsn int, opts map[string]string) (Provider, error) {
		switch vsn {
		case -1, 1:
		default:
			return nil, ErrNoProviderWithVersion
		}

		if len(opts) != 0 {
			return nil, ErrNoOptions
		}

		p := &basic{
			vsn:      1,
			endpoint: endpoint,
		}
		return p, nil
	}
}

func azureADFactory(vsn int, opts map[string]string) (Provider, error) {
	switch vsn {
	case -1, 1:
	default:
		return nil, ErrNoProviderWithVersion
	}

	tenant := opts["tenant"]
	if tenant == "" {
		return nil, &OptionError{Option: "tenant", Message: "tenant is required"}
	}

	p := &basic{
		vsn:      1,
		endpoint: microsoft.AzureADEndpoint(tenant),
	}
	return p, nil
}

func customFactory(vsn int, opts map[string]string) (Provider, error) {
	switch vsn {
	case -1, 1:
	default:
		return nil, ErrNoProviderWithVersion
	}

	authURL := opts["auth_code_url"]
	if authURL == "" {
		return nil, &OptionError{Option: "auth_code_url", Message: "authorization code URL is required"}
	}

	tokenURL := opts["token_url"]
	if tokenURL == "" {
		return nil, &OptionError{Option: "token_url", Message: "token URL is required"}
	}

	authStyle := oauth2.AuthStyleAutoDetect
	switch opts["auth_style"] {
	case "in_header":
		authStyle = oauth2.AuthStyleInHeader
	case "in_params":
		authStyle = oauth2.AuthStyleInParams
	case "":
	default:
		return nil, &OptionError{Option: "auth_style", Message: `unknown authentication style; expected one of "in_header" or "in_params"`}
	}

	endpoint := oauth2.Endpoint{
		AuthURL:   authURL,
		TokenURL:  tokenURL,
		AuthStyle: authStyle,
	}

	p := &basic{
		vsn:      1,
		endpoint: endpoint,
	}
	return p, nil
}
