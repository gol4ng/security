package provider

import (
	"errors"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type AnonymousAccess struct {
}

func (o *AnonymousAccess) Authenticate(t security.Token) (security.Token, error) {
	anonymousToken, ok := t.(*token.Anonymous)
	if !ok {
		return t, errors.New("token type not supported")
	}

	//TODO check secret validity
	anonymousToken.SetAuthenticated(true)
	return anonymousToken, nil
}

func (o *AnonymousAccess) Support(t security.Token) bool {
	_, support := t.(*token.Anonymous)
	return support
}
