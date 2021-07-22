package v2v3

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/upgrade/framework"
)

type v2ConfigEntry struct {
	Version         persistence.ConfigVersion     `json:"version"`
	ClientID        string                        `json:"client_id"`
	ClientSecret    string                        `json:"client_secret"`
	AuthURLParams   map[string]string             `json:"auth_url_params"`
	ProviderName    string                        `json:"provider_name"`
	ProviderVersion int                           `json:"provider_version"`
	ProviderOptions map[string]string             `json:"provider_options"`
	Tuning          persistence.ConfigTuningEntry `json:"tuning"`
}

type Upgrader struct {
	data    *persistence.Holder
	storage logical.Storage
}

func (*Upgrader) SentinelKey() string {
	return "v2v3"
}

func (u *Upgrader) Upgrade(ctx context.Context) error {
	// Read current configuration.
	currentConfig, err := u.readCurrentConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to read current configuration: %w", err)
	} else if currentConfig == nil || currentConfig.ClientID == "" {
		// Plugin is unconfigured or already upgraded (but sentinel failed to
		// write). Nothing further needs to be done to upgrade.
		return nil
	}

	// Create server.
	newAuthServer := &persistence.AuthServerEntry{
		ClientID:        currentConfig.ClientID,
		ClientSecret:    currentConfig.ClientSecret,
		AuthURLParams:   currentConfig.AuthURLParams,
		ProviderName:    currentConfig.ProviderName,
		ProviderVersion: currentConfig.ProviderVersion,
		ProviderOptions: currentConfig.ProviderOptions,
	}
	if err := u.data.AuthServer.Manager(u.storage).WriteAuthServerEntry(ctx, persistence.AuthServerName("legacy"), newAuthServer); err != nil {
		return fmt.Errorf("failed to create legacy server configuration: %w", err)
	}

	// Upgrade all auth code entries.
	err = u.data.AuthCode.Manager(u.storage).ForEachAuthCodeKey(ctx, func(keyer persistence.AuthCodeKeyer) error {
		return u.data.AuthCode.WithLock(keyer, func(lach *persistence.LockedAuthCodeHolder) error {
			lacm := lach.Manager(u.storage)

			entry, err := lacm.ReadAuthCodeEntry(ctx)
			if err != nil {
				return err
			}

			entry.AuthServerName = "legacy"

			if err := lacm.WriteAuthCodeEntry(ctx, entry); err != nil {
				return err
			}

			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("failed to upgrade credentials: %w", err)
	}

	// Upgrade all client credentials entries.
	err = u.data.ClientCreds.Manager(u.storage).ForEachClientCredsKey(ctx, func(keyer persistence.ClientCredsKeyer) error {
		return u.data.ClientCreds.WithLock(keyer, func(lcch *persistence.LockedClientCredsHolder) error {
			lccm := lcch.Manager(u.storage)

			entry, err := lccm.ReadClientCredsEntry(ctx)
			if err != nil {
				return err
			}

			entry.AuthServerName = "legacy"

			if err := lccm.WriteClientCredsEntry(ctx, entry); err != nil {
				return err
			}

			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("failed to upgrade credentials: %w", err)
	}

	// Write new configuration.
	newConfig := &persistence.ConfigEntry{
		Version: currentConfig.Version,
		Tuning:  currentConfig.Tuning,
	}
	if err := u.data.Config.Manager(u.storage).WriteConfig(ctx, newConfig); err != nil {
		return fmt.Errorf("failed to write new configuration: %w", err)
	}

	return nil
}

func (u *Upgrader) readCurrentConfig(ctx context.Context) (*v2ConfigEntry, error) {
	se, err := u.storage.Get(ctx, "config")
	if err != nil {
		return nil, err
	} else if se == nil {
		return nil, nil
	}

	entry := &v2ConfigEntry{}
	if err := se.DecodeJSON(entry); err != nil {
		return nil, err
	}

	return entry, nil
}

func NewUpgrader(data *persistence.Holder, storage logical.Storage) *Upgrader {
	return &Upgrader{
		data:    data,
		storage: storage,
	}
}

func Factory(data *persistence.Holder, storage logical.Storage) framework.Upgrader {
	return NewUpgrader(data, storage)
}
