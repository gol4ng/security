package anonymous

import (
	"errors"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type Authenticator struct {
}

func (o *Authenticator) Authenticate(t security.Token) (security.Token, error) {
	anonymousToken, ok := t.(*token.Anonymous)
	if !ok {
		return t, errors.New("token type not supported")
	}

	//TODO check secret validity
	anonymousToken.SetAuthenticated(true)
	return anonymousToken, nil
}

func (o *Authenticator) Support(t security.Token) bool {
	_, support := t.(*token.Anonymous)
	return support
}

func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}
