package user_password

import (
	"errors"

	"github.com/gol4ng/security"
)

var (
	ErrUserTypeNotSupported = errors.New("user type not supported")
)

type Authenticator struct {
	userProvider             security.UserProvider
	userPasswordTokenChecker TokenChecker
}

func (o *Authenticator) Authenticate(t security.Token) (security.Token, error) {
	userPasswordToken, ok := t.(TokenUserPassword)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	user, err := o.userProvider.LoadUserByUsername(userPasswordToken.GetUsername())
	if err != nil {
		return nil, err
	}

	userPassword, ok := user.(UserPassword)
	if !ok {
		return t, ErrUserTypeNotSupported
	}

	if err := o.userPasswordTokenChecker.CheckAuthentication(userPassword, userPasswordToken); err != nil {
		return nil, err
	}

	userPasswordToken.SetUser(userPassword)
	userPasswordToken.SetAuthenticated(true)
	return userPasswordToken, nil
}

func (o *Authenticator) Support(t security.Token) bool {
	_, support := t.(TokenUserPassword)
	return support
}

func NewAuthenticator(provider security.UserProvider, checker TokenChecker) *Authenticator {
	return &Authenticator{
		userProvider:             provider,
		userPasswordTokenChecker: checker,
	}
}
