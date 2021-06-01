package authentication

import (
	"context"
	"errors"

	"github.com/gol4ng/security"
)

var (
	ErrNoAuthenticationProviderFound = errors.New("no authentication provider found")
)

type ChainAuthenticator struct {
	authenticators []security.Authenticator
}

func (c *ChainAuthenticator) Authenticate(ctx context.Context, token security.Token) (security.Token, error) {
	var authenticatedToken security.Token
	var err error

	for _, authenticator := range c.authenticators {
		if !authenticator.Support(ctx, token) {
			continue
		}

		authenticatedToken, err = authenticator.Authenticate(ctx, token)
		if err == nil {
			return authenticatedToken, nil
		}
	}

	if err != nil {
		return nil, err
	}

	return nil, ErrNoAuthenticationProviderFound
}

func (c *ChainAuthenticator) Support(ctx context.Context, token security.Token) bool {
	for _, authenticator := range c.authenticators {
		if authenticator.Support(ctx, token) {
			return true
		}
	}
	return false
}

func NewChainAuthenticator(authenticators ...security.Authenticator) *ChainAuthenticator {
	return &ChainAuthenticator{
		authenticators: authenticators,
	}
}
