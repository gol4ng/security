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

func RawTokenBasicDecode(_ context.Context, rawToken *token.RawToken) (security.Token, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawToken.GetRaw())
	if err != nil {
		return rawToken, err
	}
	values := strings.Split(string(decoded), ":")
	if len(values) != 2 {
		return rawToken, ErrInvalidBasicFormat
	}

	return user_password.NewToken(values[0], values[1]), nil
}

func NewBasicAuthenticator(provider security.UserProvider, checker user_password.TokenChecker) *RawAuthenticatorWrapper {
	return NewRawAuthenticatorWrapper(NewUserPasswordAuthenticator(provider, checker), WithTokenTransformer(RawTokenBasicDecode))
}
