package provider

import (
	"context"

	gooidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/bitbucket"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/slack"
)

func init() {
	GlobalRegistry.MustRegister("bitbucket", BasicFactory(bitbucket.Endpoint))
	GlobalRegistry.MustRegister("github", BasicFactory(github.Endpoint))
	GlobalRegistry.MustRegister("gitlab", BasicFactory(gitlab.Endpoint))
	GlobalRegistry.MustRegister("google", BasicFactory(google.Endpoint))
	GlobalRegistry.MustRegister("microsoft_azure_ad", AzureADFactory)
	GlobalRegistry.MustRegister("slack", BasicFactory(slack.Endpoint))

	GlobalRegistry.MustRegister("custom", CustomFactory)
}

type basicExchangeConfig struct {
	config *oauth2.Config
}

func (c *basicExchangeConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*Token, error) {
	tok, err := c.config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}

	return &Token{Token: tok}, nil
}

func (c *basicExchangeConfig) Refresh(ctx context.Context, t *Token) (*Token, error) {
	tok, err := c.config.TokenSource(ctx, t.Token).Token()
	if err != nil {
		return nil, err
	}

	return &Token{Token: tok}, nil
}

type basicExchangeConfigBuilder struct {
	config *oauth2.Config
}

func (cb *basicExchangeConfigBuilder) WithOption(name, value string) ExchangeConfigBuilder {
	return cb
}

func (cb *basicExchangeConfigBuilder) WithRedirectURL(redirectURL string) ExchangeConfigBuilder {
	cb.config.RedirectURL = redirectURL
	return cb
}

func (cb *basicExchangeConfigBuilder) Build() ExchangeConfig {
	return &basicExchangeConfig{
		config: cb.config,
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
	return NewConformingAuthCodeURLConfigBuilder(b.endpoint, clientID)
}

func (b *basic) NewExchangeConfigBuilder(clientID, clientSecret string) ExchangeConfigBuilder {
	return &basicExchangeConfigBuilder{
		config: &oauth2.Config{
			Endpoint:     b.endpoint,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}
}

func BasicFactory(endpoint oauth2.Endpoint) FactoryFunc {
	return func(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
		vsn = selectVersion(vsn, 1)

		switch vsn {
		case 1:
		default:
			return nil, ErrNoProviderWithVersion
		}

		if len(opts) != 0 {
			return nil, ErrNoOptions
		}

		p := &basic{
			vsn:      vsn,
			endpoint: endpoint,
		}
		return p, nil
	}
}

func AzureADFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 1)

	switch vsn {
	case 1:
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

func CustomFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, 2)

	switch vsn {
	case 2:
	case 1:
		// discovery_url is now deprecated since we have a complete OIDC
		// provider, but will be honored for existing configurations.
		discoveryURL := opts["discovery_url"]
		if discoveryURL != "" {
			provider, err := gooidc.NewProvider(ctx, discoveryURL)
			if err != nil {
				return nil, &OptionError{Option: "discovery_url", Message: "error making new provider", Cause: err}
			}

			opts["auth_code_url"] = provider.Endpoint().AuthURL
			opts["token_url"] = provider.Endpoint().TokenURL
		}
	default:
		return nil, ErrNoProviderWithVersion
	}

	if opts["auth_code_url"] == "" {
		return nil, &OptionError{Option: "auth_code_url", Message: "authorization code URL is required"}
	}

	if opts["token_url"] == "" {
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
		AuthURL:   opts["auth_code_url"],
		TokenURL:  opts["token_url"],
		AuthStyle: authStyle,
	}

	p := &basic{
		vsn:      vsn,
		endpoint: endpoint,
	}
	return p, nil
}
