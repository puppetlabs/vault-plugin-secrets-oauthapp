package backend

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
)

func (b *backend) configReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.cache.Config.Get(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if cfg == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"default_server": cfg.DefaultServer,

			"tune_provider_timeout_seconds":              cfg.Tuning.ProviderTimeoutSeconds,
			"tune_provider_timeout_expiry_leeway_factor": cfg.Tuning.ProviderTimeoutExpiryLeewayFactor,

			"tune_refresh_check_interval_seconds": cfg.Tuning.RefreshCheckIntervalSeconds,
			"tune_refresh_expiry_delta_factor":    cfg.Tuning.RefreshExpiryDeltaFactor,

			"tune_reap_check_interval_seconds":   cfg.Tuning.ReapCheckIntervalSeconds,
			"tune_reap_dry_run":                  cfg.Tuning.ReapDryRun,
			"tune_reap_non_refreshable_seconds":  cfg.Tuning.ReapNonRefreshableSeconds,
			"tune_reap_revoked_seconds":          cfg.Tuning.ReapRevokedSeconds,
			"tune_reap_transient_error_attempts": cfg.Tuning.ReapTransientErrorAttempts,
			"tune_reap_transient_error_seconds":  cfg.Tuning.ReapTransientErrorSeconds,
			"tune_reap_server_deleted_seconds":   cfg.Tuning.ReapServerDeletedSeconds,
		},
	}
	return resp, nil
}

func (b *backend) configUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	c := &persistence.ConfigEntry{
		Version:       persistence.ConfigVersionLatest,
		DefaultServer: data.Get("default_server").(string),
		Tuning: persistence.ConfigTuningEntry{
			ProviderTimeoutSeconds:            data.Get("tune_provider_timeout_seconds").(int),
			ProviderTimeoutExpiryLeewayFactor: data.Get("tune_provider_timeout_expiry_leeway_factor").(float64),
			RefreshCheckIntervalSeconds:       data.Get("tune_refresh_check_interval_seconds").(int),
			RefreshExpiryDeltaFactor:          data.Get("tune_refresh_expiry_delta_factor").(float64),
			ReapCheckIntervalSeconds:          data.Get("tune_reap_check_interval_seconds").(int),
			ReapDryRun:                        data.Get("tune_reap_dry_run").(bool),
			ReapNonRefreshableSeconds:         data.Get("tune_reap_non_refreshable_seconds").(int),
			ReapRevokedSeconds:                data.Get("tune_reap_revoked_seconds").(int),
			ReapTransientErrorAttempts:        data.Get("tune_reap_transient_error_attempts").(int),
			ReapTransientErrorSeconds:         data.Get("tune_reap_transient_error_seconds").(int),
			ReapServerDeletedSeconds:          data.Get("tune_reap_server_deleted_seconds").(int),
		},
	}

	// Sanity checks for tuning options.
	switch {
	case c.Tuning.ProviderTimeoutExpiryLeewayFactor < 1:
		return logical.ErrorResponse("provider timeout expiry leeway factor must be at least 1.0"), nil
	case c.Tuning.RefreshCheckIntervalSeconds > int((90 * 24 * time.Hour).Seconds()):
		return logical.ErrorResponse("refresh check interval can be at most 90 days"), nil
	case c.Tuning.RefreshExpiryDeltaFactor < 1:
		return logical.ErrorResponse("refresh expiry delta factor must be at least 1.0"), nil
	case c.Tuning.ReapCheckIntervalSeconds > int((180 * 24 * time.Hour).Seconds()):
		return logical.ErrorResponse("reap check interval can be at most 180 days"), nil
	case c.Tuning.ReapTransientErrorAttempts < 0:
		return logical.ErrorResponse("reap transient error attempts cannot be negative"), nil
	}

	if err := b.data.Config.Manager(req.Storage).WriteConfig(ctx, c); err != nil {
		return nil, err
	}

	b.cache.Config.Invalidate()
	b.reset()

	return nil, nil
}

func (b *backend) configDeleteOperation(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := b.data.Config.Manager(req.Storage).DeleteConfig(ctx); err != nil {
		return nil, err
	}

	b.cache.Config.Invalidate()
	b.reset()

	return nil, nil
}

const (
	ConfigPath       = "config"
	ConfigPathPrefix = ConfigPath + "/"
)

var configFields = map[string]*framework.FieldSchema{
	"default_server": {
		Type:        framework.TypeString,
		Description: "The name of a server to use as a default value if no server is specified in a credentials request.",
	},
	"tune_provider_timeout_seconds": {
		Type:        framework.TypeDurationSecond,
		Description: "Specifies the maximum time to wait for a provider response in seconds. Infinite if 0.",
		Default:     persistence.DefaultConfigTuningEntry.ProviderTimeoutSeconds,
	},
	"tune_provider_timeout_expiry_leeway_factor": {
		Type:        framework.TypeFloat,
		Description: "Specifies a multiplier for the provider timeout when a credential is about to expire. Must be at least 1.",
		Default:     persistence.DefaultConfigTuningEntry.ProviderTimeoutExpiryLeewayFactor,
	},
	"tune_refresh_check_interval_seconds": {
		Type:        framework.TypeDurationSecond,
		Description: "Specifies the interval in seconds between invocations of the credential refresh background process. Disabled if 0.",
		Default:     persistence.DefaultConfigTuningEntry.RefreshCheckIntervalSeconds,
	},
	"tune_refresh_expiry_delta_factor": {
		Type:        framework.TypeFloat,
		Description: "Specifies a multipler for the refresh check interval to use to detect tokens that will expire soon after a background refresh process is invoked. Must be at least 1.",
		Default:     persistence.DefaultConfigTuningEntry.RefreshExpiryDeltaFactor,
	},
	"tune_reap_check_interval_seconds": {
		Type:        framework.TypeDurationSecond,
		Description: "Specifies the interval in seconds between invocations of the expired credential reaper background process. Disabled if 0.",
		Default:     persistence.DefaultConfigTuningEntry.ReapCheckIntervalSeconds,
	},
	"tune_reap_dry_run": {
		Type:        framework.TypeBool,
		Description: "Specifies whether the expired credential reaper should merely report on what it would delete.",
		Default:     persistence.DefaultConfigTuningEntry.ReapDryRun,
	},
	"tune_reap_non_refreshable_seconds": {
		Type:        framework.TypeDurationSecond,
		Description: "Specifies the minimum additional time to wait before automatically deleting an expired credential that does not have a refresh token. Set to 0 to disable this reaping criterion.",
		Default:     persistence.DefaultConfigTuningEntry.ReapNonRefreshableSeconds,
	},
	"tune_reap_revoked_seconds": {
		Type:        framework.TypeDurationSecond,
		Description: "Specifies the minimum additional time to wait before automatically deleting an expired credential that has a revoked refresh token. Set to 0 to disable this reaping criterion.",
		Default:     persistence.DefaultConfigTuningEntry.ReapRevokedSeconds,
	},
	"tune_reap_transient_error_attempts": {
		Type:        framework.TypeInt,
		Description: "Specifies the minimum number of refresh attempts to make before automatically deleting an expired credential. Set to 0 to disable this reaping criterion.",
		Default:     persistence.DefaultConfigTuningEntry.ReapTransientErrorAttempts,
	},
	"tune_reap_transient_error_seconds": {
		Type:        framework.TypeDurationSecond,
		Description: "Specifies the minimum additional time to wait before automatically deleting an expired credential that cannot be refreshed because of a transient problem like network connectivity issues. Set to 0 to disable this reaping criterion.",
		Default:     persistence.DefaultConfigTuningEntry.ReapTransientErrorSeconds,
	},
	"tune_reap_server_deleted_seconds": {
		Type:        framework.TypeDurationSecond,
		Description: "Specifies the minimum additional time to wait before automatically deleting an expired credential that no longer has its backing server configured.",
		Default:     persistence.DefaultConfigTuningEntry.ReapServerDeletedSeconds,
	},
}

const configHelpSynopsis = `
Configures OAuth 2.0 client information.
`

const configHelpDescription = `
This endpoint configures the endpoint, client ID, and secret for
authorization code exchange. The endpoint is selected by the given
provider. Additionally, you may specify URL parameters to add to the
authorization code endpoint.
`

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ConfigPath + `$`,
		Fields:  configFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.configReadOperation,
				Summary:  "Return the current configuration for this mount.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.configUpdateOperation,
				Summary:  "Create a new client configuration or replace the configuration with new client information.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.configDeleteOperation,
				Summary:  "Delete the client configuration, invalidating all credentials.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(configHelpSynopsis),
		HelpDescription: strings.TrimSpace(configHelpDescription),
	}
}
