package anonymous

import (
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type Token struct {
	security.Token
}

func NewToken() *Token {
	return &Token{
		Token: &token.Token{},
	}
}
