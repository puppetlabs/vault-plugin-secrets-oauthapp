package provider

import (
	"context"

	gooidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/bitbucket"
	"golang.org/x/oauth2/clientcredentials"
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

type basicOperations struct {
	base *oauth2.Config
}

func (bo *basicOperations) AuthCodeURL(state string, opts ...AuthCodeURLOption) string {
	o := &AuthCodeURLOptions{}
	o.ApplyOptions(opts)

	cfg := &oauth2.Config{}
	*cfg = *bo.base
	cfg.Scopes = o.Scopes
	cfg.RedirectURL = o.RedirectURL

	return cfg.AuthCodeURL(state, o.AuthCodeOptions...)
}

func (bo *basicOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	o := &AuthCodeExchangeOptions{}
	o.ApplyOptions(opts)

	cfg := &oauth2.Config{}
	*cfg = *bo.base
	cfg.RedirectURL = o.RedirectURL

	tok, err := cfg.Exchange(ctx, code, o.AuthCodeOptions...)
	if err != nil {
		return nil, err
	}

	return &Token{Token: tok}, nil
}

func (bo *basicOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	tok, err := bo.base.TokenSource(ctx, t.Token).Token()
	if err != nil {
		return nil, err
	}

	return &Token{Token: tok}, nil
}

func (bo *basicOperations) ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error) {
	o := &ClientCredentialsOptions{}
	o.ApplyOptions(opts)

	cc := &clientcredentials.Config{
		ClientID:       bo.base.ClientID,
		ClientSecret:   bo.base.ClientSecret,
		TokenURL:       bo.base.Endpoint.TokenURL,
		AuthStyle:      bo.base.Endpoint.AuthStyle,
		Scopes:         o.Scopes,
		EndpointParams: o.EndpointParams,
	}

	tok, err := cc.Token(ctx)
	if err != nil {
		return nil, err
	}

	return &Token{Token: tok}, nil
}

type basic struct {
	vsn      int
	endpoint oauth2.Endpoint
}

func (b *basic) Version() int {
	return b.vsn
}

func (b *basic) Public(clientID string) PublicOperations {
	return b.Private(clientID, "")
}

func (b *basic) Private(clientID, clientSecret string) PrivateOperations {
	return &basicOperations{
		base: &oauth2.Config{
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
