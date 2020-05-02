package anonymous

import (
	"github.com/gol4ng/security"
)

type Authenticator struct {
}

func (o *Authenticator) Authenticate(t security.Token) (security.Token, error) {
	anonymousToken, ok := t.(*Token)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	anonymousToken.SetAuthenticated(true)
	return anonymousToken, nil
}

func (o *Authenticator) Support(t security.Token) bool {
	_, support := t.(*Token)
	return support
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}
