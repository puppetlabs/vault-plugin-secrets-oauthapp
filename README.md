# vault-plugin-secrets-oauthapp

This is a standalone backend plugin for use with [HashiCorp
Vault](https://github.com/hashicorp/vault).

This plugin provides a secure wrapper around OAuth 2 authorization code, refresh
token, device code, and client credentials grant types, allowing a Vault client
to request authorization on behalf of a user and perform actions using a
negotiated OAuth 2 access token.

## Usage

Once you have the binary, you will need to register the plugin with Vault.
Follow [the instructions in the Vault
documentation](https://www.vaultproject.io/docs/internals/plugins.html#plugin-registration)
to add the plugin to the catalog. We will assume it is registered under the name
`oauthapp`.

Enable the plugin at the path of your choosing:

```
$ vault secrets enable -path=oauth2 oauthapp
Success! Enabled the oauthapp secrets engine at: oauth2/
```

Configure it with the necessary information to exchange tokens:

```
$ vault write oauth2/servers/github-puppetlabs \
    provider=github \
    client_id=aBcD3FgHiJkLmN0pQ \
    client_secret=AbCd3fGh1jK1MnoPqRs7uVwXYz
Success! Data written to: oauth2/servers/github-puppetlabs
```

Once the client secret has been written, it will never be exposed again.

You can have as many server configurations as you need for your use case,
although it is common to only have one. Server configurations need not share the
same provider.

It is also possible to configure a default server:

```
$ vault write oauth2/config default_server=github-puppetlabs
Success! Data written to: oauth2/config
```

When a default server is set in the plugin configuration, it isn't necessary to
specify the `server` field when writing credentials.

### Authorization code exchange flow

From a Vault client, request an authorization code URL:

```
$ vault write oauth2/auth-code-url \
    server=github-puppetlabs \
    state=foo \
    scopes=bar,baz
Key    Value
---    -----
url    https://github.com/login/oauth/authorize?client_id=aBcD3FgHiJkLmN0pQ&response_type=code&scope=bar+baz&state=foo
```

If you don't specify a state value, the plugin will generate one for you and return it in the response as well.

After redirecting the user to that URL and receiving the resulting temporary
authorization code in your callback handler, you can create a permanent
credential that automatically refreshes:

```
$ vault write oauth2/creds/my-user-auth \
    server=github-puppetlabs \
    code=zYxWvU7sRqP
Success! Data written to: oauth2/creds/my-user-auth
```

Assuming the refresh token remains valid, an access token is available any time at the same endpoint:

```
$ vault read oauth2/creds/my-user-auth
Key             Value
---             -----
access_token    nLlBg9Lmd7n1X96bw/xcW9HvyOHzxj19z3zXKv0XXxr8eLjQSerf4iyPDRCucSHQN+c7fnKhPsSWbWg0
server          github-puppetlabs
type            Bearer
```

Note that the client secret and refresh token are never exposed to Vault
clients.

Alternatively, if a refresh token is obtained in some other way you can
skip the auth code URL step and pass the token directly to the creds
write instead of the response code:

```
$ vault write oauth2/creds/my-user-auth \
    server=github-puppetlabs \
    grant_type=refresh_token \
    refresh_token=TGUgZ3JpbGxlPw==
Success! Data written to: oauth2/creds/my-user-auth
```

### Device code flow

The [device code](https://oauth.net/2/grant-types/device-code/) grant type
allows a user to authenticate outside of a browser session. This plugin supports
the device code flow and automatically handles polling the authorization server
for a valid access token.

Not all providers support device code grants. Check the provider's documentation for more information.

To initiate the device code flow:

```
$ vault write oauth2/creds/my-user-auth \
    server=github-puppetlabs \
    grant_type=urn:ietf:params:oauth:grant-type:device_code
Key                 Value
---                 -----
expire_time         2021-03-10T23:35:00.295229233Z
user_code           BDWD-HQPK
verification_uri    https://github.com/login/device
```

The plugin will manage the device code (similar to a refresh token) and will
never present it to you. You should forward the user code and verification URL
to the authorization subject for them to take action to log in.

Initially, when you try to read the credential back, you'll get an error letting
you know the token is pending issuance because the user hasn't yet performed the
required verification steps:

```
$ vault read oauth2/creds/my-user-auth
Error reading oauth2/creds/my-user-auth: Error making API request.

URL: GET http://localhost:8200/v1/oauth2/creds/my-user-auth
Code: 400. Errors:

* token pending issuance
```

However, within a few seconds of the user verifying their identity, you should
see the access token:

```
$ vault read oauth2/creds/my-user-auth
Key             Value
---             -----
access_token    aGVsbG8gaGVsbG8gaGVsbG8K
expire_time     2021-03-27T00:15:38.72796606Z
server          github-puppetlabs
type            Bearer
```

### Client credentials flow

From a Vault client, configure a server that supports the client credentials
grant type and write a credential under the `self` endpoint that references the
server:

```
$ vault write oauth2/servers/auth0-example \
    provider=oidc \
    provider_options=issuer_url=https://dev-example.us.auth0.com/ \
    client_id=aBcD3FgHiJkLmN0pQ \
    client_secret=AbCd3fGh1jK1MnoPqRs7uVwXYz
Success! Data written to: oauth2/servers/auth0-example
```
```
$ vault write oauth2/self/my-machine-auth \
    server=auth0-example \
    token_url_params=audience=https://dev-example.us.auth0.com/api/v2/ \
    scopes=read:users
Success! Data written to: oauth2/self/my-machine-auth
```

The token will be negotiated on demand going forward using the desired
configuration:

```
$ vault read oauth2/self/my-machine-auth
Key                 Value
---                 -----
access_token        SSBhbSBzbyBzbWFydC4gUy1NLVItVC4=
expire_time         2021-01-16T15:38:21.105335834Z
scopes              [read:users]
server              auth0-example
token_url_params    map[audience:https://dev-example.us.auth0.com/api/v2/]
type                Bearer
```

## Tips

For some operations, you may find that you need to provide a map of data for a
field. When using the Vault CLI, you can repeat the name of the field for each
key-value pair of the map and use `=` to separate keys from values. For example:

```
$ vault write oauth2/servers/oidc-example \
    provider_options=issuer_url=https://login.example.com \
    provider_options=extra_data_fields=id_token_claims
```

## Upgrading

For instructions on how to upgrade from previous versions of the plugin, see the
[UPGRADING](UPGRADING.md) document.

## Performance tuning

There are several categories of performance tuning options you may want to
adjust to get the most out of this plugin. All of the options are fields set
when writing this plugin's configuration to the `config` endpoint.

### Provider timeouts

It can be inconvenient when a provider you're working with doesn't respond to
requests in a reasonable time. Therefore, we apply a default timeout of 30
seconds to all outbound requests. We also allow for a bit of leeway when a token
is getting close to its expiry, preferring to wait longer to avoid clients
having to retry requests to Vault. This is applied using a logarithmic algorithm
relative to the usual grace period we'd use for refreshing.

You can set the initial provider timeout using the
`tune_provider_timeout_seconds` option. If you set it to 0, we won't apply any
timeout.

The default leeway factor is 1.5, i.e., a maximum timeout of 45 seconds when a
token is close to expiration. You can set a different factor using the
`tune_provider_timeout_expiry_leeway_factor` option. To disable timeout scaling,
set the leeway factor to 1.

The provider timeout is applied when a request is made to a provider. If a
plugin endpoint might make multiple requests to a provider, for example if
multiple client secrets are specified in a server configuration, the total
request time for a client of this plugin may be significantly higher than the
value of the provider timeout.

### Automatic refreshing

To avoid having to contact providers when tokens are read from storage and need
to be refreshed, this plugin will automatically check and attempt to refresh
tokens that are close to expiring on a regular interval. The default check
interval is 1 minute. The refresh check has a grace period, called the expiry
delta, that extends beyond the refresh check interval to allow for some overlap.
The default expiry delta factor is 1.2, or 72 seconds.

You can set the refresh check interval using the
`tune_refresh_check_interval_seconds` option and the expiry delta factor using
the `tune_refresh_expiry_delta_factor` option.

If you don't need this behavior, for example because your provider doesn't use
refresh tokens, you can set `tune_refresh_check_interval_seconds` to 0.

Alternatively, if you have a relatively small number of tokens and your provider
issues tokens with very long expirations, you may want to use a longer refresh
interval than the default to avoid having to loop over all credentials in
storage every minute.

### Automatic reaping

There are a number of situations that result in stored tokens becoming unusable.
Broadly, we group these into the following categories:

* Expired with no refresh token
* Expired and refresh failed because the provider rejected the refresh request
* Expired and enough transient errors have occurred to discard the token (for
  example, instead of rejecting a token, the provider hangs the connection)
* Expired and the server referenced by the credential no longer exists

This plugin can automatically delete tokens that are expired and meet one of
these criteria using a process called reaping. Like the automatic refreshing,
reaping runs on an interval, by default 5 minutes. You can change the reap
interval using the `tune_reap_check_interval_seconds` option.

You can disable the reaper entirely by setting the option to 0, or you can
enable a dry run mode using the `tune_reap_dry_run` option. When in dry run
mode, you can check your Vault server logs to see which credentials would be
deleted.

The criteria are mutually exclusive, so for example, a token that has a provider
refresh rejection will always have that criterion applied to it, even if it also
has transient errors.

Each of the criteria have their own tuning options documented in the `config`
endpoint. Note that the defaults should be reasonable for most users. You can
disable any of the criteria by setting its corresponding option to 0.

## Endpoints

### `config`

#### `GET` (`read`)

Retrieve the current configuration settings.

#### `PUT` (`write`)

Write new configuration settings. This endpoint completely replaces the existing
configuration, so you must specify all desired fields, even when updating.

Parameters:

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `default_server` | The name of the authorization server to use as a default if not specified when configuring a credential. | String | None<sup id="ret-1">[1](#footnote-1)</sup> | No |
| `tune_provider_timeout_seconds` | Maximum duration to wait for a response from the provider for background credential operations. | Integer | 30 | No |
| `tune_provider_timeout_expiry_leeway_factor` | A multiplier for the `tune_provider_timeout_seconds` option to allow a slow provider to respond as a credential approaches expiration. Must be at least 1. | Number | 1.5 | No |
| `tune_refresh_check_interval_seconds` | Number of seconds between checking tokens for refresh. Set to 0 to disable automatic background refreshing. | Integer | 60 | No |
| `tune_refresh_expiry_delta_factor` | A multiplier for the refresh check interval to use to detect tokens that will expire soon after the impending refresh. Must be at least 1. | Number | 1.2 | No |
| `tune_reap_check_interval_seconds` | Number of seconds between running the reaper process. Set to 0 to disable automatic reaping of expired credentials. | Integer | 300<sup id="ret-2">[2](#footnote-2)</sup> | No |
| `tune_reap_dry_run` | If set, the reaper process will only report which credentials it would remove, but not actually delete them from storage. | Boolean | False | No |
| `tune_reap_non_refreshable_seconds` | Minimum additional time to wait before automatically deleting an expired credential that does not have a refresh token. Set to 0 to disable this reaping criterion. | Integer | 86400 | No |
| `tune_reap_revoked_seconds` | Minimum additional time to wait before automatically deleting an expired credential that has a revoked refresh token. Set to 0 to disable this reaping criterion. | Integer | 3600 | No |
| `tune_reap_transient_error_attempts` | Minimum number of refresh attempts to make before automatically deleting an expired credential. Set to 0 to disable this reaping criterion. | Integer | 10 | No |
| `tune_reap_transient_error_seconds` | Minimum additional time to wait before automatically deleting an expired credential that cannot be refreshed because of a transient problem like network connectivity issues. Set to 0 to disable this reaping criterion. | Integer | 86400 | No |
| `tune_reap_server_deleted_seconds` | Minimum additional time to wait before automatically deleting an expired credential that no longer references a valid server. Set to 0 to disable this reaping criterion. | Integer | 86400 | No |

#### `DELETE` (`delete`)

Remove the current configuration, resetting tuning options to the plugin
defaults.

### `servers`

#### `GET` (`list`)

Show the names of all currently available servers.

### `servers/:name`

#### `GET` (`read`)

Retrieve the configuration for a given server (except the client secret).

#### `PUT` (`write`)

Create or update the configuration for a given server.

Parameters:

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `client_id` | The OAuth 2.0 client ID. | String | None | Yes |
| `client_secret` | The OAuth 2.0 client secret. Prepended to the value of `client_secrets` if it is also present. | String | None | No |
| `client_secrets` | An ordered list of OAuth 2.0 client secrets to try. Appended to the value of `client_secret` if it is also present. | List of String | None | No |
| `auth_url_params` | A map of additional query string parameters to provide to the authorization code URL. | Map of String🠦String | None | No |
| `provider` | The name of the provider to use. See [the list of providers](#providers). | String | None | Yes |
| `provider_options` | Options to configure the specified provider. | Map of String🠦String | None | [Refer to provider documentation](#providers) |

#### `DELETE` (`delete`)

Remove the configuration for a given server. Note that this does not revoke any
stored credentials that reference the server name, but those credentials will no
longer be able to be updated automatically.

If you write a new server configuration with the same name, existing credentials
that reference the server will start to use it.

### `auth-code-url`

#### `PUT` (`write`)

Retrieve an authorization code URL for the given server. Some providers may not
provide the plugin with information about this URL, in which case accessing this
endpoint will return an error.

This operation does not change any underlying storage, but because the state
parameter is sensitive, we use a write operation and include it in the request
body to prevent proxies from inadvertently logging it.

Parameters:

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `server` | The name of a server to use for the authorization code exchange flow. Inherits from the plugin configuration's `default_server` field if present, and may override it. | String | Inherited | Yes |
| `auth_url_params` | A map of additional query string parameters to provide to the authorization code URL. If any keys in this map conflict with the parameters stored in the configuration, the configuration's parameters take precedence. | Map of String🠦String | None | No |
| `redirect_url` | The URL to redirect to once the user has authorized this application. | String | None | No |
| `scopes` | A list of explicit scopes to request. | List of String | None | No |
| `state` | The unique state to send to the authorization URL. Automatically generated if not provided. | String | None | No |
| `provider_options` | A list of options to pass on to the provider for configuring the authorization code URL. | Map of String🠦String | None | [Refer to provider documentation](#providers) |

### `creds/:name`

This path is for tokens to be obtained using the OAuth 2.0 authorization code,
refresh token, and device code flows.

#### `GET` (`read`)

Retrieve a current access token for the given credential. Reuses previous token
if it is not yet expired or close to it. Otherwise, requests a new access
token using the saved refresh token if possible.

Parameters:

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `minimum_seconds` | Minimum additional duration to require the access token to be valid for. | Integer | 10<sup id="ret-3-a">[3](#footnote-3)</sup> | No |
| `scopes` | A list of explicit scopes to request. | List of String | None | No |
| `audience` | A list of explicit audiences to request. | List of String | None | No |
| `resource` | A list of explicit resources to request. | List of String | None | No |

If scopes, audience, and/or resource is requested, an access token that
is more limited according to those requested parameters than the
corresponding refresh token is returned.  The more limited access token
is not cached for later requests; the less limited one is cached as usual.

#### `PUT` (`write`)

Create or update a credential using a supported three-legged flow. This
operation will make a request for a new credential using the specified grant
type.

Parameters:

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `server` | The name of a server to use for the credential flow. Inherits from the plugin configuration's `default_server` field if present, and may override it. | String | Inherited | Yes |
| `grant_type` | The grant type to use. Must be one of `authorization_code`, `refresh_token`, or `urn:ietf:params:oauth:grant-type:device_code`. | String | `authorization_code`<sup id="ret-4">[4](#footnote-4)</sup> | Yes |
| `maximum_expiry_seconds` | The upper limit for a token's valid duration. The lesser of this value and the expiry provided in the response will be used. If the server does not provide an expiry (i.e., the server considers the token to be valid indefinitely), this parameter takes precedence and the token will be refreshed if possible. | Integer | None | No |
| `provider_options` | A list of options to pass on to the provider for configuring this token exchange. | Map of String🠦String | None | [Refer to provider documentation](#providers) |

This operation takes additional parameters depending on which grant type is
chosen:

##### `authorization_code` (default)

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `code` | The response code to exchange for a full token. | String | None | Yes |
| `redirect_url` | The same redirect URL as specified in the authorization code URL. | String | None | Refer to provider documentation |

##### `refresh_token`

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `refresh_token` | The refresh token retrieved from the provider by some means external to this plugin. | String | None | Yes |

##### `urn:ietf:params:oauth:grant-type:device_code`

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `device_code` | A device code that has already been retrieved. If not specified, a new device code will be retrieved. | String | None | No |
| `scopes` | If a device code is not specified, the scopes to request. | List of String | None | No |

#### `DELETE` (`delete`)

Remove the credential information from storage. This does not revoke the token,
so keep in mind that applications may hold any requested access token until its
expiry.

### `self/:name`

This path is for tokens to be obtained using the OAuth 2.0 client credentials
flow.

#### `GET` (`read`)

Retrieve a current access token for the underlying OAuth 2.0 application. Reuses
previous token if it is not yet expired or close to it. Otherwise, requests a
new credential using the `client_credentials` grant type.

Parameters:

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `minimum_seconds` | Minimum additional duration to require the access token to be valid for. | Integer | 10<sup id="ret-3-b">[3](#footnote-3)</sup> | No |

#### `PUT` (`write`)

Configure a client credentials grant for the credential with the given name.
Writing configuration will cause a new token to be retrieved and validated using
the `client_credentials` grant type.

Parameters:

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `server` | The name of a server to use for the credential flow. Inherits from the plugin configuration's `default_server` field if present, and may override it. | String | Inherited | Yes |
| `token_url_params` | A map of additional query string parameters to provide to the token URL. | Map of String🠦String | None | No |
| `scopes` | A list of explicit scopes to request. | List of String | None | No |
| `maximum_expiry_seconds` | The upper limit for a token's valid duration. The lesser of this value and the expiry provided in the response will be used. If the server does not provide an expiry (i.e., the server considers the token to be valid indefinitely), this parameter takes precedence. | Integer | None | No |
| `provider_options` | A list of options to pass on to the provider for configuring this token exchange. | Map of String🠦String | None | No |

#### `DELETE` (`delete`)

Remove the credential information from storage.

## Providers

### Bitbucket (`bitbucket`)

[Documentation](https://developer.atlassian.com/cloud/bitbucket/oauth-2/)

### GitHub (`github`)

[Documentation](https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/)

### GitLab (`gitlab`)

[Documentation](https://docs.gitlab.com/ee/api/oauth2.html)

### Google (`google`)

[Documentation](https://developers.google.com/identity/protocols/oauth2)

#### Configuration options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `extra_data_fields` | A comma-separated list of subject fields to expose in the credential endpoint. Valid fields are `id_token`, `id_token_claims`, and `user_info`. | None | No |

#### Credential options

| Name | Description | Supported flows | Default | Required |
|------|-------------|-----------------|---------|----------|
| `nonce` | The same nonce as specified in the authorization code URL. | Authorization code exchange | None | If present in the authorization code URL |

### Microsoft Azure AD (`microsoft_azure_ad`)

[Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)

#### Configuration options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `tenant` | The tenant to authenticate to. | `organizations` | No |

#### Authorization code URL options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `tenant` | The tenant to authenticate to. Ignored if the `tenant` option is specified in the server configuration. | Inherited | No |

#### Credential options

| Name | Description | Supported flows | Default | Required |
|------|-------------|-----------------|---------|----------|
| `tenant` | The tenant to authenticate to. Ignored if the `tenant` option is specified in the server configuration. | All | Inherited | No |

### OpenID Connect (`oidc`)

This provider implements the OpenID Connect protocol version 1.0.

[Documentation](https://openid.net/developers/specs/)

#### Configuration options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `issuer_url` | The URL to an issuer of OpenID JWTs with an accessible `.well-known/openid-configuration` resource. | None | Yes |
| `extra_data_fields` | A comma-separated list of subject fields to expose in the credential endpoint. Valid fields are `id_token`, `id_token_claims`, and `user_info`. | None | No |

#### Credential options

| Name | Description | Supported flows | Default | Required |
|------|-------------|-----------------|---------|----------|
| `nonce` | The same nonce as specified in the authorization code URL. | Authorization code exchange | None | If present in the authorization code URL |

### Slack (`slack`)

[Documentation](https://api.slack.com/docs/oauth)

### Custom (`custom`)

This provider allows you to specify the required endpoints for negotiating an
arbitrary OAuth 2 authorization code grant flow.

#### Configuration options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `auth_code_url` | The URL to submit the initial authorization code request to. | None | No |
| `device_code_url` | The URL to subject a device authorization request to. | None | No |
| `token_url` | The URL to use for exchanging temporary codes and refreshing access tokens. | None | Yes |
| `auth_style` | How to authenticate to the token URL. If specified, must be one of `in_header` or `in_params`. | Automatically detect | No |


## Footnotes

<span id="footnote-1"><sup>1</sup> For users upgrading from versions prior to 3.0.0, the default server will automatically be set to a legacy server for backward compatibility. <small>[↩](#ret-1)</small></span>

<span id="footnote-2"><sup>2</sup> For users upgrading from versions prior to
2.2.0 with valid configurations, the reaper will not be automatically enabled
unless you replace your configuration. <small>[↩](#ret-2)</small></span>

<span id="footnote-3"><sup>3</sup> The default is 10 seconds as specified in the
Go [OAuth 2.0 library](https://github.com/golang/oauth2) unless the token does
not expire. <small>↩ [a](#ret-3-a) [b](#ret-3-b)</small></span>

<span id="footnote-4"><sup>4</sup> For compatibility, if `grant_type` is not
provided and `refresh_token` is set, the `grant_type` will default to
`refresh_token`. <small>[↩](#ret-4)</small></span>
