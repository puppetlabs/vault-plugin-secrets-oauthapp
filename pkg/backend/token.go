package backend

import (
	"time"

	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"golang.org/x/oauth2"
)

const (
	defaultExpiryDelta = 10 * time.Second
)

func tokenExpired(clk clock.Clock, t *oauth2.Token, expiryDelta time.Duration) bool {
	if t.Expiry.IsZero() {
		return false
	}

	if expiryDelta < defaultExpiryDelta {
		expiryDelta = defaultExpiryDelta
	}

	return t.Expiry.Round(0).Add(-expiryDelta).Before(clk.Now())
}

func (b *backend) tokenValid(tok *oauth2.Token, expiryDelta time.Duration) bool {
	return tok != nil && tok.AccessToken != "" && !tokenExpired(b.clock, tok, expiryDelta)
}
