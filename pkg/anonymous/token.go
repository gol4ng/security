package anonymous

import (
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type Token struct {
	security.Token
	secret string
}

func NewToken(secret string) *Token {
	return &Token{
		Token:  &token.Token{},
		secret: secret,
	}
}
