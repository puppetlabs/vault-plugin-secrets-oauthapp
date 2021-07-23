# Upgrading

This document describes the steps a Vault operator needs to take when upgrading
from one version of this plugin to another. Note that this plugin only supports
upgrading one major version at a time. Do not attempt to upgrade, for example,
from a v1 release to a v3 release without upgrading to v2 first.

## v2→v3

### Automated upgrade

V3 of this plugin removes support for global configuration of providers. When
you activate v3 of this plugin for the first time on an engine previously
enabled with v2, it will automatically upgrade the global configuration to the
new server configuration format. In particular, it will:

1. Create a new server called "legacy" that contains the same provider
   configuration as the v2 `config` endpoint.
1. Iterate over all stored credentials and associate the new "legacy" server
   with them.
1. Remove the provider configuration from the `config` endpoint.

Depending on the number of credentials stored, this operation may take a few
seconds. This will allow the plugin to continue servicing existing credentials
without interruption.

Once an engine is upgraded to v3, it is not possible to roll back to v2.
Therefore, you should back up your physical storage before this upgrade.

### Required consumer changes

Broadly speaking, clients should not require any changes when reading data under
the `creds/:name` endpoint. When writing a new credential to `creds/:name`, it
is now _required_ to specify the server name to use in the `server` parameter.

The `config/self/:name` endpoint has been removed, and it is no longer possible
to dynamically perform a client credentials flow for a previously nonexistent
credential. The options from `config/self/:name`, along with a now-required
`server` parameter, have been moved to `self/:name`. In v3 of this plugin, you
must write to `self/:name` before attempting to read from it.

The `config/auth_code_url` endpoint has been removed. Consumers of this plugin
should use the `auth-code-url` endpoint instead. It is now _required_ to specify
the server name to use in the `server` parameter for this endpoint.

## v2.*x*→v2.2

### Optional consumer changes

v2.2 of this plugin provides a reaper process that can automatically remove
expired or otherwise unusable credentials. This process is enabled by default
for new installations, but not for existing engines.

If you want to enable the reaper after upgrading to v2.2, overwrite the `config`
endpoint with a new configuration. Note that it is not necessary to specify the
tuning options; the defaults will be used when the configuration is written.

If you need to update your configuration and do not want to enable the reaper,
you must set the `tune_reap_check_interval_seconds` option to 0.

## v1→v2

### Required consumer changes

The `self/:name/config` endpoint has been renamed to `config/self/:name`.
