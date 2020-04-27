package jwt

import (
	"github.com/dgrijalva/jwt-go"
	security_token "github.com/gol4ng/security/token"
)

type Token struct {
	security_token.Token

	jwtToken *jwt.Token
}

func (t *Token) GetJWTToken() *jwt.Token {
	return t.jwtToken
}

func (t *Token) GetClaims() jwt.Claims {
	return t.jwtToken.Claims
}

func NewToken(jwtToken *jwt.Token) *Token {
	return &Token{
		jwtToken: jwtToken,
	}
}
