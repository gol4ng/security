package jwt

import (
	"github.com/dgrijalva/jwt-go"
)

type Parser interface {
	GetClaims(token string) (jwt.Claims, error)
}

type ParserWithPublicKey struct {
	publicKey string
}

func NewParserWithECDSA(publicKey string) Parser {
	return &ParserWithPublicKey{publicKey}
}

func (p ParserWithPublicKey) GetClaims(t string) (jwt.Claims, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		return []byte(p.publicKey), nil
	})

	if token == nil {
		return nil, err
	}

	return token.Claims, err
}
