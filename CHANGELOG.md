# Changelog

We document all notable changes to this project in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.1.1] - 2023-02-02

### Fixed

* The `sts/:name` endpoint should have been seal-wrapped like the corresponding
  `creds/:name` endpoint.

## [3.1.0] - 2023-01-23

### Added

* Add support for configuring the maximum valid lifetime of a token with a new
  `maximum_expiry_seconds` parameter on the `creds/:name` and `self/:name`
  endpoints.
* The OAuth 2.0 token exchange flow (RFC 8693) for impersonation is now
  supported by reading from the `sts/:name` endpoint.

## [3.0.0] - 2021-09-20

### Added

* It is now possible to manage multiple authorization servers at the same time
  by writing separate provider configurations to the `servers/:name` endpoint.
  Listing servers is supported at the `servers` endpoint.
* Additionally, server configurations support a new `client_secrets` field that
  was not present in the plugin configuration in v2. When this field is set to a
  list, the plugin will attempt to use each secret in order until it receives a
  successful provider response.
* The plugin configuration supports selecting a default server to use by setting
  the `default_server` field. When upgrading from v2, this field will be
  automatically set to maintain backward compatibility.
* It is no longer necessary to explicitly specify a state when requesting an
  authorization code URL. The plugin will generate a random state and return it
  in the response.
* Add the new tuning option `tune_reap_server_deleted_seconds` to control how
  long the plugin should wait before automatically deleting credentials that
  refer to a nonexistent (deleted) server.

### Changed

* [BREAKING] The plugin configuration no longer supports configuring a single
  provider for the entire engine. Instead, configure a provider using the new
  `servers/:name` endpoint and reference it in credentials.
* [BREAKING] The `config/auth_code_url` endpoint has been removed and replaced
  by the `auth-code-url` endpoint, which accepts a server name as a parameter.
* [BREAKING] The `config/self/:name` endpoint has been removed, and it is no
  longer possible to store an access token using the client credentials flow by
  reading from an unconfigured path at the `self/:name` endpoint. Instead,
  initialize such an access token by writing to the `self/:name` endpoint with
  any necessary configuration first.
* The device code flow support library now sends an `Accept: application/json`
  header to improve compatibility with legacy device code endpoints that support
  both JSON and form-encoded responses.

### Fixed

* The scheduled processes for refreshing credentials, reaping credentials, and
  managing the device code flow no longer start on a Vault server configured as
  a performance secondary, performance standby, or disaster recovery secondary.

### Build

* Remove darwin/386 from distribution as it is no longer supported by Go or
  Vault.

## [2.2.0] - 2021-07-13

### Added

* Add additional performance tuning options for provider timeouts and automatic
  credential reaping.

## [2.1.1] - 2021-06-25

### Fixed

* Fix a regression that caused the automatic credential refresher to be disabled
  on configurations written before v2.1.0.

## [2.1.0] - 2021-06-24

### Added

* Add support for multi-tenant Azure AD apps. This is done by giving an ability
  to set the `tenant` provider option on a per-credential basis if not
  explicitly specified in the provider configuration. If no tenant is provided,
  the tenant now defaults to allowing any Azure AD account.
* The check interval for refreshing tokens is now configurable using the
  `tune_refresh_check_interval_seconds` option. It can also be explicitly
  disabled by setting the interval to 0.

### Changed

* The Google provider now uses an OpenID implementation, which allows it to also
  retrieve data from the `id_token`. Write a new plugin configuration to take
  advantage of this feature.

## [2.0.0] - 2021-04-09

### Changed

* [BREAKING] The path to configure a token for client credentials exchange has
  changed from `self/:name/config` to `config/self/:name`.
* [BREAKING] Deleting a client credentials exchange token no longer also deletes
  the configuration associated with it. To also delete the configuration, delete
  `config/self/:name` instead.
* The names of credentials are now unrestricted, except that they cannot end
  with a colon (`:`) character or have a colon immediately before a slash (`/`).

## [1.10.1] - 2021-04-07

### Fixed

* Fix a regression that caused the `minimum_seconds` field of a credential read
  request to be ignored.
* Correctly request updated user information when an OIDC token is refreshed.

## [1.10.0] - 2021-03-29

### Added

* The OAuth 2.0 device authorization flow (RFC 8628) is now supported by
  specifying `grant_type=urn:ietf:params:oauth:grant-type:device_code` when
  creating a credential.

### Changed

* Specifying a client secret when configuring the engine is now optional.

## [1.9.0] - 2021-01-19

### Added

* The OAuth 2.0 client credentials flow is now supported using the new `self`
  endpoints.

### Fixed

* Errors caused by configuration problems in the OIDC provider are now correctly
  propagated to the HTTP response with a 400 status code.
* The `nonce` provider option for the OIDC authorization code exchange is now
  passed to the ID token verification routine.
* Nonce validation is only performed during OIDC authorization code exchange or
  refresh token flow if the plugin user specifies a nonce to validate against;
  otherwise, it is assumed that the nonce data is invalid or non-conforming to
  the OpenID Connect Core specification.
* Per the OpenID Connect Core specification, ID tokens will only be revalidated
  during refresh if the server sends a new ID token. Otherwise, they are passed
  through unmodified from the original exchange.

### Changed

* The `testutil` package now uses a `*provider.Token` instead of a
  `*oauth2.Token` for mocks, allowing the `ExtraData` to be customized.
* It is now optional for providers to expose an authorization code URL.

## [1.8.3] - 2020-12-17

### Build

* Allow combined workflow to upload actual archives in addition to checksums.

## [1.8.2] - 2020-12-17

### Build

* Combine CI and release workflows so that release assets can be attached.

## [1.8.1] - 2020-12-17

### Build

* Fix workflow configuration to properly create GitHub releases.

## [1.8.0] - 2020-12-17

### Added

* Add support for OpenID Connect as a provider.

### Changed

* Use a collection of locks (256, distributed uniformly among credential keys)
  instead of a global mutex to improve performance.
* Because we now have a more complete OpenID Connect provider, the option to
  provide a `discovery_url` to the custom provider has been removed. Existing
  configurations that make use of the `discovery_url` will continue to work as
  intended.

### Build

* Switch to GitHub Actions and remove dependency on semantic-release.

## [1.7.0] - 2020-10-27

### Added

* Add `minimum_seconds` credential read option.

## [1.6.0] - 2020-09-28

### Added

* Allow additional characters in credential names.

## [1.5.0] - 2020-09-28

### Changed

* Log error codes from exchanging or refreshing tokens for debugging.

## [1.4.0] - 2020-09-28

### Added

* Add `discovery_url` provider option to the custom provider to allow discovery
  of a corresponding OAuth 2 endpoint.

## [1.3.0] - 2020-07-13

### Added

* Add support for Google as a provider.

## [1.2.0] - 2020-04-06

### Added

* Add `refresh_token` field when writing a new credential to handle cases where
  the OAuth 2 exchange initially occurred out of band.

## [1.1.1] - 2019-10-07

### Fixed

* Do not propagate API errors from providers when token refresh fails.

## [1.1.0] - 2019-09-19

### Added

* The token type is now returned as part of the credential read operation.

## [1.0.0] - 2019-09-18

### Added

* Initial release of the plugin.

[Unreleased]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v3.1.1...HEAD
[3.1.1]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v3.1.0...v3.1.1
[3.1.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v2.2.0...v3.0.0
[2.2.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.10.1...v2.0.0
[1.10.1]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.8.3...v1.9.0
[1.8.3]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/puppetlabs/vault-plugin-secrets-oauthapp/compare/3322c7fdad569beefe2f476e977b38f8a87e18a4...v1.0.0
