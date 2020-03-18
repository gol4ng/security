package authentication

import (
	"errors"

	"github.com/gol4ng/security"
)

type ChainAuthenticator struct {
	authenticators []security.Authenticator
}

func (c *ChainAuthenticator) Authenticate(token security.Token) (security.Token, error) {
	var authenticatedToken security.Token
	var err error

	for _, authenticator := range c.authenticators {
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

func (c *ChainAuthenticator) Support(token security.Token) bool {
	for _, authenticator := range c.authenticators {
		if authenticator.Support(token) {
			return true
		}
	}
	return false
}

func NewChainAuthenticator(providers ...security.Authenticator) *ChainAuthenticator {
	return &ChainAuthenticator{
		authenticators: providers,
	}
}
