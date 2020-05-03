package token

import (
	"github.com/gol4ng/security"
)

type Anonymous struct {
	security.Token
}

func NewAnonymousToken() *Anonymous {
	return &Anonymous{
		Token: &Token{},
	}
}
