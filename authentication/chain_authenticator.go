package authentication

import (
	"errors"

	"github.com/gol4ng/security"
)

type ChainAuthenticator struct {
	providers []Provider
}

func (c *ChainAuthenticator) Authenticate(token security.Token) (authenticatedToken security.Token, err error) {
	for _, authenticator := range c.providers {
		if authenticator.Support(token) {
			authenticatedToken, err = authenticator.Authenticate(token)
			if err == nil {
				return
			}
		}
	}
	if err != nil {
		return
	}
	return nil, errors.New("no authentication provider found")
}

func NewChainAuthenticator(providers ...Provider) *ChainAuthenticator {
	return &ChainAuthenticator{
		providers: providers,
	}
}
