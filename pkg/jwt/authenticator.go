package jwt

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
	"github.com/gol4ng/security/user"
)

var (
	ErrUsernameNotFound = errors.New("username not found")
	ErrInvalidTokenJWT  = errors.New("invalid JWT Token")
)

type Authenticator struct {
	parser         Parser
	usernameGetter UsernameGetter
}

func (a Authenticator) Authenticate(t security.Token) (security.Token, error) {
	var outputToken *Token
	rawToken, ok := t.(*token.RawToken)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	jwtToken, err := a.parser.Parse(rawToken.GetRaw())
	outputToken = NewToken(jwtToken)
	if err != nil {
		return outputToken, err
	}

	if !jwtToken.Valid {
		return outputToken, ErrInvalidTokenJWT
	}

	username := a.usernameGetter(jwtToken.Claims)
	if username == "" {
		return outputToken, ErrUsernameNotFound
	}

	outputToken.SetUser(user.NewUser(username))
	outputToken.SetAuthenticated(true)

	return outputToken, nil
}

func (a *Authenticator) Support(t security.Token) bool {
	_, support := t.(*token.RawToken)
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
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	sub, ok := mapClaims["sub"]
	if !ok {
		return ""
	}

	s, ok := sub.(string)
	if !ok {
		return ""
	}

	return s
}
