module github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2

go 1.14

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/golangci/golangci-lint v1.33.0
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/vault/api v1.0.5-0.20200519221902-385fac77e20f
	github.com/hashicorp/vault/sdk v0.2.0
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/puppetlabs/leg/errmap v0.1.0
	github.com/puppetlabs/leg/scheduler v0.3.0
	github.com/puppetlabs/leg/timeutil v0.4.1
	github.com/spf13/afero v1.2.2 // indirect
	github.com/stretchr/testify v1.6.1
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	google.golang.org/appengine v1.6.2 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1
	gotest.tools/gotestsum v0.6.0
	k8s.io/apimachinery v0.20.1
)
