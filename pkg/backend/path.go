package backend

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// nameRegex allows any character other than a : followed by a /, which allows
// us to specially reserve a small subset of possible names for future derived
// credentials (STS).
func nameRegex(name string) string {
	return fmt.Sprintf(`(?P<%s>(?:[^:]|:[^/])+)`, name)
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
		pathConfigSelf(b),
		pathCreds(b),
		pathSelf(b),
	}
}
