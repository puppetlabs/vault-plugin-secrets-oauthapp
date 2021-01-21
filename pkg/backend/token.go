package backend

import (
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/pkg/provider"
)

func tokenValid(tok *provider.Token, data *framework.FieldData) bool {
	if tok == nil || !tok.Valid() {
		return false
	}
	if data == nil {
		return true
	}
	if minsecondsstr, ok := data.GetOk("minimum_seconds"); ok {
		minseconds := minsecondsstr.(int)
		zeroTime := time.Time{}
		if tok.Expiry != zeroTime && time.Until(tok.Expiry).Seconds() < float64(minseconds) {
			return false
		}
	}
	return true
}
