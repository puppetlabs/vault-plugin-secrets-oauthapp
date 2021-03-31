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

Mount the plugin at the path of your choosing:

```
$ vault secrets enable -path=oauth2/bitbucket oauthapp
Success! Enabled the oauthapp secrets engine at: oauth2/bitbucket/
```

Configure it with the necessary information to exchange tokens:

```
$ vault write oauth2/bitbucket/config \
    provider=bitbucket \
    client_id=aBcD3FgHiJkLmN0pQ \
    client_secret=AbCd3fGh1jK1MnoPqRs7uVwXYz
Success! Data written to: oauth2/bitbucket/config
```

Once the client secret has been written, it will never be exposed again.

### Authorization code exchange flow

From a Vault client, request an authorization code URL:

```
$ vault write oauth2/bitbucket/config/auth_code_url state=foo scopes=bar,baz
Key    Value
---    -----
url    https://bitbucket.org/site/oauth2/authorize?client_id=aBcD3FgHiJkLmN0pQ&response_type=code&scope=bar+baz&state=foo
```

After redirecting the user to that URL and receiving the resulting temporary
authorization code in your callback handler, you can create a permanent
credential that automatically refreshes:

```
$ vault write oauth2/bitbucket/creds/my-user-auth code=zYxWvU7sRqP
Success! Data written to: oauth2/bitbucket/creds/my-user-auth
```

Assuming the refresh token remains valid, an access token is available any time at the same endpoint:

```
$ vault read oauth2/bitbucket/creds/my-user-auth
Key             Value
---             -----
access_token    nLlBg9Lmd7n1X96bw/xcW9HvyOHzxj19z3zXKv0XXxr8eLjQSerf4iyPDRCucSHQN+c7fnKhPsSWbWg0
```

Note that the client secret and refresh token are never exposed to Vault
clients.

Alternatively, if a refresh token is obtained in some other way you can
skip the auth_code_url step and pass the token directly to the creds
write instead of the response code:

```
$ vault write oauth2/bitbucket/creds/my-user-auth \
    grant_type=refresh_token \
    refresh_token=TGUgZ3JpbGxlPw==
Success! Data written to: oauth2/bitbucket/creds/my-user-auth
```

### Device code flow

The [device code](https://oauth.net/2/grant-types/device-code/) grant type
allows a user to authenticate outside of a browser session. This plugin supports
the device code flow and automatically handles polling the authorization server
for a valid access token.

Not all providers support device code grants. Check the provider's documentation for more information.

To initiate the device code flow (this time using [GitHub as an
example](https://docs.github.com/en/developers/apps/authorizing-oauth-apps#device-flow)):

```
$ vault write oauth2/github/creds/my-user-auth grant_type=urn:ietf:params:oauth:grant-type:device_code
Key                 Value
---                 -----
user_code           BDWD-HQPK
verification_uri    https://github.com/login/device
expire_time         2021-03-10T23:35:00.295229233Z
```

The plugin will manage the device code (similar to a refresh token) and will
never present it to you. You should forward the user code and verification URL
to the authorization subject for them to take action to log in.

Initially, when you try to read the credential back, you'll get an error letting
you know the token is pending issuance because the user hasn't yet performed the
required verification steps:

```
$ vault read oauth2/github/creds/my-user-auth
Error reading oauth2/github/creds/my-user-auth: Error making API request.

URL: GET http://localhost:8200/v1/oauth2/github/creds/my-user-auth
Code: 400. Errors:

* token pending issuance
```

However, within a few seconds of the user verifying their identity, you should
see the access token:

```
$ vault read oauth2/github/creds/my-user-auth
Key             Value
---             -----
access_token    aGVsbG8gaGVsbG8gaGVsbG8K
expire_time     2021-03-27T00:15:38.72796606Z
type            Bearer
```

### Client credentials flow

From a Vault client, simply read an arbitrary token using the `self` endpoints:

```
$ vault read oauth2/bitbucket/self/my-machine-auth
Key             Value
---             -----
access_token    SSBhbSBzbyBzbWFydC4gUy1NLVItVC4=
expire_time     2021-01-16T15:38:21.105335834Z
type            Bearer
```

You can configure the parameters of the identity provider's token endpoint if
needed:

```
$ vault write oauth2/bitbucket/self/my-machine-auth/config \
    scopes=repositories:read
Success! Data written to: oauth2/bitbucket/self/my-machine-auth/config
```

## Tips

For some operations, you may find that you need to provide a map of data for a
field. When using the CLI, you can repeat the name of the field for each
key-value pair of the map and use `=` to separate keys from values. For example:

```
$ vault write oauth2/oidc/config \
    provider_options=issuer_url=https://login.example.com \
    provider_options=extra_data_fields=id_token_claims
```

## Endpoints

### `config`

#### `GET` (`read`)

Retrieve the current configuration settings (except the client secret).

#### `PUT` (`write`)

Write new configuration settings. This endpoint completely replaces the existing
configuration, so you must specify all required fields, even when updating.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `client_id` | The OAuth 2.0 client ID. | String | None | Yes |
| `client_secret` | The OAuth 2.0 client secret. | String | None | No |
| `auth_url_params` | A map of additional query string parameters to provide to the authorization code URL. | Map of String🠦String | None | No |
| `provider` | The name of the provider to use. See [the list of providers](#providers). | String | None | Yes |
| `provider_options` | Options to configure the specified provider. | Map of String🠦String | None | No |

#### `DELETE` (`delete`)

Remove the current configuration. This does not invalidate any existing access
tokens; however, you will not be able to create new tokens or refresh existing
tokens.

### `config/auth_code_url`

#### `PUT` (`write`)

Retrieve an authorization code URL for the given state. Some providers may not
provide the plugin with information about this URL, in which case accessing this
endpoint will return an error.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `auth_url_params` | A map of additional query string parameters to provide to the authorization code URL. If any keys in this map conflict with the parameters stored in the configuration, the configuration's parameters take precedence. | Map of String🠦String | None | No |
| `redirect_url` | The URL to redirect to once the user has authorized this application. | String | None | No |
| `scopes` | A list of explicit scopes to request. | List of String | None | No |
| `state` | The unique state to send to the authorization URL. | String | None | Yes |

### `creds/:name`

This path is for tokens to be obtained using the OAuth 2.0 authorization code,
refresh token, and device code flows.

#### `GET` (`read`)

Retrieve a current access token for the given credential. Reuses previous token
if it is not yet expired or close to it. Otherwise, requests a new credential
using the `refresh_token` grant type if possible.

If scopes or audience are requested, the current access token will be
exchanged for another access token with more limited scopes or audience,
and the more limited token returned.
The more limited token is not saved for reuse; the less limited one is
saved as usual.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `minimum_seconds` | Minimum seconds before access token expires. | Integer | * | No |
| `scopes` | A list of explicit scopes to request. | List of String | None | No |
| `audience` | An explicit audience to request. | String | None | No |

\* Defaults to underlying library default, which is 10 seconds unless
  the token expiration time is set to zero.

#### `PUT` (`write`)

Create or update a credential using a supported three-legged flow. This
operation will make a request for a new credential using the specified grant
type.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `grant_type` | The grant type to use. Must be one of `authorization_code`, `refresh_token`, or `urn:ietf:params:oauth:grant-type:device_code`. | String | `authorization_code`* | No |
| `provider_options` | A list of options to pass on to the provider for configuring this token exchange. | Map of String🠦String | None | Refer to provider documentation |

This operation takes additional fields depending on which grant type is chosen:

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

\* For compatibility, if `grant_type` is not provided and `refresh_token` is set, the `grant_type` will default to `refresh_token`.

#### `DELETE` (`delete`)

Remove the credential information from storage.

### `self/:name`

This path is for tokens to be obtained using the OAuth 2.0 client credentials
flow.

#### `GET` (`read`)

Retrieve a current access token for the underlying OAuth 2.0 application. Reuses
previous token if it is not yet expired or close to it. Otherwise, requests a
new credential using the `client_credentials` grant type.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `minimum_seconds` | Minimum seconds before access token expires | Integer | * | No |

\* Defaults to underlying library default, which is 10 seconds unless
  the token expiration time is set to zero.

#### `DELETE` (`delete`)

Remove the credential information from storage.

### `self/:name/config`

#### `GET` (`read`)

Retrieve the configuration for the given credential, if any is present.

#### `PUT` (`write`)

Configure the credential for the given name. Writing configuration will cause a
new token to be retrieved and validated using the `client_credentials` grant
type.

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `token_url_params` | A map of additional query string parameters to provide to the token URL. If any keys in this map conflict with the parameters stored in the configuration, the configuration's parameters take precedence. | Map of String🠦String | None | No |
| `scopes` | A list of explicit scopes to request. | List of String | None | No |

## Providers

### Bitbucket (`bitbucket`)

[Documentation](https://developer.atlassian.com/cloud/bitbucket/oauth-2/)

### GitHub (`github`)

[Documentation](https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/)

### GitLab (`gitlab`)

[Documentation](https://docs.gitlab.com/ee/api/oauth2.html)

### Google (`google`)

[Documentation](https://developers.google.com/identity/protocols/oauth2)

### Microsoft Azure AD (`microsoft_azure_ad`)

[Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)

#### Configuration options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `tenant` | The tenant to authenticate to. | None | Yes |

### OpenID Connect (`oidc`)

This provider implements the OpenID Connect protocol version 1.0.

[Documentation](https://openid.net/developers/specs/)

#### Configuration options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `issuer_url` | The URL to an issuer of OpenID JWTs with an accessible `.well-known/openid-configuration` resource. | None | Yes |
| `extra_data_fields` | A comma-separated list of subject fields to expose in the credential endpoint. Valid fields are `id_token`, `id_token_claims`, and `user_info`. | None | No |

#### Credential exchange options

| Name | Description | Default | Required |
|------|-------------|---------|----------|
| `nonce` | The same nonce as specified in the authorization code URL. | None | If present in the authorization code URL |

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
