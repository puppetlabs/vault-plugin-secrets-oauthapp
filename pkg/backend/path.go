package backend

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// nameRegex allows most printable ASCII characters in path names that are not
// slashes.
func nameRegex(name string) string {
	return fmt.Sprintf(`(?P<%s>\w(([\w.@~!_,:^-]+)?\w)?)`, name)
}

func pathsSpecial() *logical.Paths {
	return &logical.Paths{
		SealWrapStorage: []string{
			configPath,
			credsPathPrefix,
			selfPathPrefix,
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
