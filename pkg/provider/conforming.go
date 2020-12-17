package provider

import "golang.org/x/oauth2"

type ConformingAuthCodeURLConfigBuilder struct {
	config *oauth2.Config
}

func (cb *ConformingAuthCodeURLConfigBuilder) WithRedirectURL(redirectURL string) AuthCodeURLConfigBuilder {
	cb.config.RedirectURL = redirectURL
	return cb
}

func (cb *ConformingAuthCodeURLConfigBuilder) WithScopes(scopes ...string) AuthCodeURLConfigBuilder {
	cb.config.Scopes = scopes
	return cb
}

func (cb *ConformingAuthCodeURLConfigBuilder) Build() AuthCodeURLConfig {
	return cb.config
}

func NewConformingAuthCodeURLConfigBuilder(endpoint oauth2.Endpoint, clientID string) *ConformingAuthCodeURLConfigBuilder {
	return &ConformingAuthCodeURLConfigBuilder{
		config: &oauth2.Config{
			Endpoint: endpoint,
			ClientID: clientID,
		},
	}
}
