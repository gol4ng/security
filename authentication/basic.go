package authentication

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/pkg/user_password"
	"github.com/gol4ng/security/token"
)

type BasicAuthenticator struct {
	authenticator *user_password.Authenticator
}

func (o *BasicAuthenticator) Authenticate(t security.Token) (security.Token, error) {
	basicToken, ok := t.(*token.RawToken)
	if !ok {
		return t, errors.New("token type not supported")
	}

	decoded, err := base64.StdEncoding.DecodeString(basicToken.GetRaw())
	if err != nil {
		return t, err
	}
	values := strings.Split(string(decoded), ":")
	if len(values) != 2 {
		return t, errors.New("cannot find username and password")
	}

	return o.authenticator.Authenticate(user_password.NewToken(values[0], values[1]))
}
func (o *BasicAuthenticator) Support(t security.Token) bool {
	_, support := t.(*token.RawToken)
	return support
}

func NewBasicAuthenticator(authenticator *user_password.Authenticator) *BasicAuthenticator {
	return &BasicAuthenticator{
		authenticator: authenticator,
	}
}
