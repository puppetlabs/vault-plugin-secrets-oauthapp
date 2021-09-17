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
		Name: persistence.LegacyAuthServerName,

		ClientID:        currentConfig.ClientID,
		AuthURLParams:   currentConfig.AuthURLParams,
		ProviderName:    currentConfig.ProviderName,
		ProviderVersion: currentConfig.ProviderVersion,
		ProviderOptions: currentConfig.ProviderOptions,
	}
	if currentConfig.ClientSecret != "" {
		newAuthServer.ClientSecrets = []string{currentConfig.ClientSecret}
	}
	if err := u.data.AuthServer.Manager(u.storage).WriteAuthServerEntry(ctx, persistence.AuthServerName(newAuthServer.Name), newAuthServer); err != nil {
		return fmt.Errorf("failed to create legacy server configuration: %w", err)
	}

	// Write new configuration.
	newConfig := &persistence.ConfigEntry{
		Version:       currentConfig.Version,
		DefaultServer: newAuthServer.Name,
		Tuning:        currentConfig.Tuning,
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
