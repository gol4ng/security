package jwt

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/user"
)

var ErrAuthenticationFailed = errors.New("authentication failed")

type Authenticator struct {
	parser         Parser
	usernameGetter UsernameGetter
}

func (a Authenticator) Authenticate(t security.Token) (authenticatedToken security.Token, err error) {
	jwtToken, ok := t.(*Token)
	if !ok {
		return t, errors.New("token type not supported")
	}

	claims, err := a.parser.GetClaims(jwtToken.GetToken())
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

func (a *Authenticator) Support(t security.Token) bool {
	_, support := t.(*Token)
	return support
}

func (a *Authenticator) apply(options ...AuthenticatorOption) *Authenticator {
	for _, option := range options {
		option(a)
	}
	return a
}

// AuthOption defines a interceptor middleware configuration option
type AuthenticatorOption func(*Authenticator)

func NewAuthenticator(parser Parser, options ...AuthenticatorOption) *Authenticator {
	return (&Authenticator{
		parser:         parser,
		usernameGetter: DefaultUsernameGetter,
	}).apply(options...)
}

func WithUsernameGetter(getter UsernameGetter) AuthenticatorOption {
	return func(authenticator *Authenticator) {
		authenticator.usernameGetter = getter
	}
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
