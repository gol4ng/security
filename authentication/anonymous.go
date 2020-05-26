package authentication

import (
	"context"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type Anonymous struct {
}

func (o *Anonymous) Authenticate(_ context.Context, t security.Token) (security.Token, error) {
	anonymousToken, ok := t.(*token.Anonymous)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	anonymousToken.SetAuthenticated(true)
	return anonymousToken, nil
}

func (o *Anonymous) Support(_ context.Context, t security.Token) bool {
	_, support := t.(*token.Anonymous)
	return support
}

func NewAnonymousAuthenticator() *Anonymous {
	return &Anonymous{}
}
