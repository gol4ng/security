package authentication

import (
	"errors"

	"github.com/gol4ng/security"
)

type ChainAuthenticator struct {
	providers []Provider
}

func (c *ChainAuthenticator) Authenticate(token security.Token) (security.Token, error) {
	var authenticatedToken security.Token
	var err error

	for _, authenticator := range c.providers {
		if !authenticator.Support(token) {
			continue
		}

		authenticatedToken, err = authenticator.Authenticate(token)
		if err == nil {
			return authenticatedToken, nil
		}
	}

	if err != nil {
		return nil, err
	}

	return nil, errors.New("no authentication provider found")
}

func NewChainAuthenticator(providers ...Provider) *ChainAuthenticator {
	return &ChainAuthenticator{
		providers: providers,
	}
}
