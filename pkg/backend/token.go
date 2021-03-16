package backend

import (
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

const (
	defaultExpiryDelta = 30 * time.Second
)

func tokenExpired(clk clock.Clock, t *provider.Token, data *framework.FieldData) bool {
	if t.Expiry.IsZero() {
		return false
	}

	var expiryDelta time.Duration
	if data != nil {
		if expiryDeltaSeconds, ok := data.GetOk("minimum_seconds"); ok {
			expiryDelta = time.Duration(expiryDeltaSeconds.(int)) * time.Second
		}
	}
	if expiryDelta < defaultExpiryDelta {
		expiryDelta = defaultExpiryDelta
	}

	return t.Expiry.Round(0).Add(-expiryDelta).Before(clk.Now())
}

func (b *backend) tokenValid(tok *provider.Token, data *framework.FieldData) bool {
	return tok != nil && tok.AccessToken != "" && !tokenExpired(b.clock, tok, data)
}
