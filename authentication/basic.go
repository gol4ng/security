package authentication

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/pkg/user_password"
	"github.com/gol4ng/security/token"
)

var (
	ErrInvalidBasicFormat = errors.New("invalid basic format")
)

type Basic struct {
	authenticator *user_password.Authenticator
}

func (o *Basic) Authenticate(t security.Token) (security.Token, error) {
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

	return o.authenticator.Authenticate(user_password.NewToken(values[0], values[1]))
}

func (o *Basic) Support(t security.Token) bool {
	_, support := t.(*token.RawToken)
	return support
}

func NewBasicAuthenticator(provider security.UserProvider, checker user_password.TokenChecker) *Basic {
	return &Basic{
		authenticator: user_password.NewAuthenticator(
			provider,
			checker,
		),
	}
}
