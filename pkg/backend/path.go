package backend

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// nameRegex allows characters not special to urls or shells,
//  plus any additional characters passed in as extras
// Derived from framework.GenericNameWithAtRegex
func nameRegex(name, extras string) string {
	return fmt.Sprintf(`(?P<%s>\w(([\w.@~!_,`+extras+`:^-]+)?\w)?)`, name)
}

func pathsSpecial() *logical.Paths {
	return &logical.Paths{
		SealWrapStorage: []string{
			ConfigPath,
			CredsPathPrefix,
			SelfPathPrefix,
		},
	}
}

func paths(b *backend) []*framework.Path {
	return []*framework.Path{
		pathConfig(b),
		pathConfigAuthCodeURL(b),
		pathCreds(b),
		pathSelf(b),
		pathSelfConfig(b),
	}
}
