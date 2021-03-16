package backend

import (
	"time"

	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

const (
	defaultExpiryDelta = 10 * time.Second
)

func tokenExpired(clk clock.Clock, t *provider.Token, expiryDelta time.Duration) bool {
	if t.Expiry.IsZero() {
		return false
	}

	if expiryDelta < defaultExpiryDelta {
		expiryDelta = defaultExpiryDelta
	}

	return t.Expiry.Round(0).Add(-expiryDelta).Before(clk.Now())
}

func (b *backend) tokenValid(tok *provider.Token, expiryDelta time.Duration) bool {
	return tok != nil && tok.AccessToken != "" && !tokenExpired(b.clock, tok, expiryDelta)
}
