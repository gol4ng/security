package authentication

import (
	"context"

	"github.com/gol4ng/httpware/v4/auth"
	"github.com/gol4ng/security"
)

type AuthenthicatorAdapter struct {
	authenticator security.Authenticator
}

func (adapter *AuthenthicatorAdapter) Authenticate(ctx context.Context, credential auth.Credential) (auth.Credential, error) {
	t, ok := credential.(security.Token)
	if !ok {
		return nil, security.ErrTokenTypeNotSupported
	}
	return adapter.authenticator.Authenticate(ctx, t)
}

func NewAuthenticatorAdapter(authenticator security.Authenticator) *AuthenthicatorAdapter {
	return &AuthenthicatorAdapter{authenticator: authenticator}
}
