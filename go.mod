module github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3

go 1.16

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/golangci/golangci-lint v1.33.0
	github.com/hashicorp/go-hclog v1.1.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/golang-lru v0.5.4
	github.com/hashicorp/vault v1.9.9
	github.com/hashicorp/vault/api v1.3.1
	github.com/hashicorp/vault/sdk v0.3.1-0.20220721224749-00773967ab3a
	github.com/puppetlabs/leg/errmap v0.1.1
	github.com/puppetlabs/leg/scheduler v0.3.0
	github.com/puppetlabs/leg/timeutil v0.4.2
	github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2 v2.2.0
	github.com/stretchr/testify v1.7.0
	github.com/tencentcloud/tencentcloud-sdk-go v3.0.171+incompatible // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
	gopkg.in/square/go-jose.v2 v2.6.0
	gotest.tools/gotestsum v0.6.0
	k8s.io/apimachinery v0.22.2
)
