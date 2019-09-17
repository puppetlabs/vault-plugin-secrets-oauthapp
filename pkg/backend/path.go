package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathsSpecial() *logical.Paths {
	return &logical.Paths{
		SealWrapStorage: []string{
			configPath,
			credsPathPrefix,
		},
	}
}

func paths(b *backend) []*framework.Path {
	return []*framework.Path{
		pathConfig(b),
		pathConfigAuthCodeURL(b),
		pathCreds(b),
	}
}
