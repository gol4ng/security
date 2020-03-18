package jwt

import (
	"github.com/dgrijalva/jwt-go"
	security_token "github.com/gol4ng/security/token"
)

type Token struct {
	security_token.Token

	token  string
	claims jwt.Claims
}

func (t *Token) GetToken() string {
	return t.token
}

func (t *Token) SetClaims(claims jwt.Claims) {
	t.claims = claims
}

func (t *Token) GetClaims() jwt.Claims {
	return t.claims
}

func NewToken(token string) *Token {
	return &Token{
		token: token,
	}
}
