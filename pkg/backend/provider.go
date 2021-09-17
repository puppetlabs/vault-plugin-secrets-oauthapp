package backend

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/devicecode"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/provider"
)

var providerErrorFormatIndenter = strings.NewReplacer("\n", "\n\t\t\t")

func providerErrorFormat(es []error) string {
	if len(es) == 1 {
		return es[0].Error()
	}

	var buf strings.Builder
	buf.WriteString("provider request failed for all client secrets:")
	for _, err := range es {
		// This formatting is weird because the response is already wrapped in a
		// multierror once (automatically by the Vault SDK) so we create one
		// further level of indentation to make it clear to the user that these
		// errors belong to the parent error.
		buf.WriteString("\n\t\t* ")
		_, _ = providerErrorFormatIndenter.WriteString(&buf, err.Error())
	}

	return buf.String()
}

type multiError = multierror.Error

type providerError struct {
	*multiError
}

var _ errmap.MapApplicator = &providerError{}

func (pe *providerError) MapApply(m errmap.Mapper) error {
	// Copy without errors.
	err := &multiError{}
	*err = *pe.multiError
	err.Errors = make([]error, 0, len(pe.Errors))

	// Map errors and copy them in.
	for _, rerr := range pe.Errors {
		err = multierror.Append(err, m.Map(rerr))
	}

	return &providerError{err}
}

type providerOperations struct {
	entry    *persistence.AuthServerEntry
	provider provider.Provider
}

func (po *providerOperations) AuthCodeURL(state string, opts ...provider.AuthCodeURLOption) (string, bool) {
	opts = append([]provider.AuthCodeURLOption{}, opts...)
	opts = append(opts, provider.WithURLParams(po.entry.AuthURLParams))

	return po.provider.Public(po.entry.ClientID).AuthCodeURL(state, opts...)
}

func (po *providerOperations) DeviceCodeAuth(ctx context.Context, opts ...provider.DeviceCodeAuthOption) (*devicecode.Auth, bool, error) {
	return po.provider.Public(po.entry.ClientID).DeviceCodeAuth(ctx, opts...)
}

func (po *providerOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...provider.DeviceCodeExchangeOption) (*provider.Token, error) {
	return po.provider.Public(po.entry.ClientID).DeviceCodeExchange(ctx, deviceCode, opts...)
}

func (po *providerOperations) RefreshToken(ctx context.Context, t *provider.Token, opts ...provider.RefreshTokenOption) (*provider.Token, error) {
	if len(po.entry.ClientSecrets) == 0 {
		return po.provider.Public(po.entry.ClientID).RefreshToken(ctx, t, opts...)
	}

	err := &multierror.Error{ErrorFormat: providerErrorFormat}
	for _, clientSecret := range po.entry.ClientSecrets {
		rt, rerr := po.provider.Private(po.entry.ClientID, clientSecret).RefreshToken(ctx, t, opts...)
		if rerr == nil {
			return rt, nil
		}

		err = multierror.Append(err, rerr)
	}

	return nil, &providerError{err}
}

func (po *providerOperations) AuthCodeExchange(ctx context.Context, code string, opts ...provider.AuthCodeExchangeOption) (*provider.Token, error) {
	if len(po.entry.ClientSecrets) == 0 {
		return nil, errmark.MarkUser(provider.ErrMissingClientSecret)
	}

	err := &multierror.Error{ErrorFormat: providerErrorFormat}
	for _, clientSecret := range po.entry.ClientSecrets {
		rt, rerr := po.provider.Private(po.entry.ClientID, clientSecret).AuthCodeExchange(ctx, code, opts...)
		if rerr == nil {
			return rt, nil
		}

		err = multierror.Append(err, rerr)
	}

	return nil, &providerError{err}
}

func (po *providerOperations) ClientCredentials(ctx context.Context, opts ...provider.ClientCredentialsOption) (*provider.Token, error) {
	if len(po.entry.ClientSecrets) == 0 {
		return nil, errmark.MarkUser(provider.ErrMissingClientSecret)
	}

	err := &multierror.Error{ErrorFormat: providerErrorFormat}
	for _, clientSecret := range po.entry.ClientSecrets {
		rt, rerr := po.provider.Private(po.entry.ClientID, clientSecret).ClientCredentials(ctx, opts...)
		if rerr == nil {
			return rt, nil
		}

		err = multierror.Append(err, rerr)
	}

	return nil, &providerError{err}
}

func (b *backend) getProviderOperations(ctx context.Context, storage logical.Storage, keyer persistence.AuthServerKeyer, expiryDelta time.Duration) (*providerOperations, func(), error) {
	cfg, err := b.cache.Config.Get(ctx, storage)
	if err != nil {
		return nil, nil, err
	}

	server, err := b.cache.AuthServer.Get(ctx, storage, keyer)
	if err != nil {
		return nil, nil, err
	} else if server == nil {
		return nil, nil, errmark.MarkUser(ErrNoSuchServer)
	}

	tuning := persistence.DefaultConfigTuningEntry
	if cfg != nil {
		tuning = cfg.Tuning
	}

	p := server.Provider
	if tuning.ProviderTimeoutSeconds > 0 {
		p = provider.NewTimeoutProvider(
			p,
			provider.NewBoundedLogarithmicTimeoutAlgorithm(
				tuning.ProviderTimeoutExpiryLeewayFactor,
				time.Duration(tuning.ProviderTimeoutSeconds)*time.Second,
				expiryDelta,
			),
		)
	}

	ops := &providerOperations{
		entry:    server.AuthServerEntry,
		provider: p,
	}
	return ops, server.Put, nil
}
