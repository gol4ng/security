package jwt

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/user"
)

var ErrAuthenticationFailed = errors.New("authentication failed")

type JWTAuthenticator struct {
	Parser         Parser
	usernameGetter UsernameGetter
}


func (a JWTAuthenticator) Authenticate(t security.Token) (authenticatedToken security.Token, err error) {
	jwtToken, ok := t.(*Token)
	if !ok {
		return t, errors.New("token type not supported")
	}

	claims, err := a.Parser.GetClaims(jwtToken.GetToken())
	if err != nil {
		return t, ErrAuthenticationFailed
	}

	username := a.usernameGetter(claims)
	if username == "" {
		return t, errors.New("username not found")
	}

	jwtToken.SetUser(user.NewUser(username))
	jwtToken.SetAuthenticated(true)
	jwtToken.SetClaims(claims)

	return jwtToken, nil
}

func (a *JWTAuthenticator) Support(t security.Token) bool {
	_, support := t.(*Token)
	return support
}

func NewJWTAuthenticator(parser Parser, usernameGetter UsernameGetter) *JWTAuthenticator {
	return &JWTAuthenticator{
		Parser: parser,
		usernameGetter: usernameGetter,
	}
}

func NewDefaultJWTAuthenticator(parser Parser) *JWTAuthenticator {
	return NewJWTAuthenticator(parser, DefaultUsernameGetter)
}

type UsernameGetter func(claims jwt.Claims) string

func DefaultUsernameGetter(claims jwt.Claims) string {
	c, ok := claims.(jwt.MapClaims)
	if !ok {
		return ""
	}

	sub, ok := c["sub"]
	if !ok {
		return ""
	}

	s, ok := sub.(string)
	if !ok {
		return ""
	}

	return s
}
