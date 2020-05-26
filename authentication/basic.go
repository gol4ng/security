package authentication

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
	"github.com/gol4ng/security/user_password"
)

var (
	ErrInvalidBasicFormat = errors.New("invalid basic format")
)

type Basic struct {
	authenticator *UserPasswordAuthenticator
}

func (o *Basic) Authenticate(ctx context.Context, t security.Token) (security.Token, error) {
	basicToken, ok := t.(*token.RawToken)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	decoded, err := base64.StdEncoding.DecodeString(basicToken.GetRaw())
	if err != nil {
		return t, err
	}
	values := strings.Split(string(decoded), ":")
	if len(values) != 2 {
		return t, ErrInvalidBasicFormat
	}

	return o.authenticator.Authenticate(ctx, user_password.NewToken(values[0], values[1]))
}

func (o *Basic) Support(_ context.Context, t security.Token) bool {
	_, support := t.(*token.RawToken)
	return support
}

func NewBasicAuthenticator(provider security.UserProvider, checker user_password.TokenChecker) *Basic {
	return &Basic{
		authenticator: NewUserPasswordAuthenticator(
			provider,
			checker,
		),
	}
}

type Basic2 struct {
	authenticator *UserPasswordAuthenticator
}

func (o *Basic2) Authenticate(ctx context.Context, t security.Token) (security.Token, error) {
	basicToken, ok := t.(*token.RawToken)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	decoded, err := base64.StdEncoding.DecodeString(basicToken.GetRaw())
	if err != nil {
		return t, err
	}
	values := strings.Split(string(decoded), ":")
	if len(values) != 2 {
		return t, ErrInvalidBasicFormat
	}

	return o.authenticator.Authenticate(ctx, user_password.NewToken(values[0], values[1]))
}

func (o *Basic2) Support(_ context.Context, t security.Token) bool {
	_, support := t.(*token.RawToken)
	return support
}

func NewBasic2Authenticator(provider security.UserProvider, checker user_password.TokenChecker) *Basic {
	return &Basic{
		authenticator: NewUserPasswordAuthenticator(
			provider,
			checker,
		),
	}
}
