module github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3

go 1.16

require (
	cloud.google.com/go/kms v1.8.0 // indirect
	cloud.google.com/go/monitoring v1.11.0 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/golangci/golangci-lint v1.50.1
	github.com/hashicorp/go-hclog v1.3.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-uuid v1.0.3
	github.com/hashicorp/golang-lru v0.5.4
	github.com/hashicorp/vault v1.12.2
	github.com/hashicorp/vault/api v1.8.0
	github.com/hashicorp/vault/sdk v0.6.1-0.20221102145943-1e9b0a1225c3
	github.com/puppetlabs/leg/errmap v0.1.1
	github.com/puppetlabs/leg/scheduler v0.3.0
	github.com/puppetlabs/leg/timeutil v0.4.2
	github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2 v2.2.0
	github.com/shirou/gopsutil v3.21.5+incompatible // indirect
	github.com/stretchr/testify v1.8.1
	github.com/tencentcloud/tencentcloud-sdk-go v3.0.171+incompatible // indirect
	github.com/tidwall/pretty v1.0.1 // indirect
	golang.org/x/oauth2 v0.0.0-20221014153046-6fdb5e3db783
	gopkg.in/square/go-jose.v2 v2.6.0
	gotest.tools/gotestsum v0.6.0
	k8s.io/apimachinery v0.22.2
)
