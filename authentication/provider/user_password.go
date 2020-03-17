package provider

import (
	"errors"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type UserPassword struct {
	userProvider             security.UserProvider
	userPasswordTokenChecker UserPasswordTokenChecker
}

func (o *UserPassword) Authenticate(t security.Token) (security.Token, error) {
	userPasswordToken, ok := t.(*token.UserPassword)
	if !ok {
		return t, errors.New("token type not supported")
	}

	user, err := o.userProvider.LoadUserByUsername(userPasswordToken.GetUsername())
	userPassword, ok := user.(security.UserPassword)
	if !ok {
		return t, errors.New("user type not supported")
	}

	if err != nil {
		return nil, err
	}

	if err := o.userPasswordTokenChecker.CheckAuthentication(userPassword, userPasswordToken); err != nil {
		return nil, err
	}

	userPasswordToken.SetUser(user)
	userPasswordToken.SetAuthenticated(true)
	return userPasswordToken, nil
}

func (o *UserPassword) Support(t security.Token) bool {
	_, support := t.(*token.UserPassword)
	return support
}

func NewUserPassword(provider security.UserProvider, checker UserPasswordTokenChecker) *UserPassword {
	return &UserPassword{
		userProvider:             provider,
		userPasswordTokenChecker: checker,
	}
}
