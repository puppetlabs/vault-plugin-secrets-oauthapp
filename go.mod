module github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3

go 1.16

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/golangci/golangci-lint v1.33.0
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/golang-lru v0.5.4
	github.com/hashicorp/vault v1.8.5
	github.com/hashicorp/vault/api v1.1.2-0.20210713235431-1fc8af4c041f
	github.com/hashicorp/vault/sdk v0.2.2-0.20211101151547-6654f4b913f9
	github.com/puppetlabs/leg/errmap v0.1.1
	github.com/puppetlabs/leg/scheduler v0.3.0
	github.com/puppetlabs/leg/timeutil v0.4.2
	github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2 v2.2.0
	github.com/spf13/cast v1.3.0
	github.com/stretchr/testify v1.7.0
	github.com/tencentcloud/tencentcloud-sdk-go v3.0.171+incompatible // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	gopkg.in/square/go-jose.v2 v2.5.1
	gotest.tools/gotestsum v0.6.0
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1 // indirect
)
