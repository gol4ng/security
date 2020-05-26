package authentication

import (
	"context"
	"errors"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/user"
	"github.com/gol4ng/security/user_password"
)

var (
	ErrUserTypeNotSupported = errors.New("user type not supported")
)

type UserPasswordAuthenticator struct {
	userProvider             security.UserProvider
	userPasswordTokenChecker user_password.TokenChecker
}

func (o *UserPasswordAuthenticator) Authenticate(ctx context.Context, t security.Token) (security.Token, error) {
	userPasswordToken, ok := t.(user_password.TokenUserPassword)
	if !ok {
		return t, security.ErrTokenTypeNotSupported
	}

	u, err := o.userProvider.LoadUserByUsername(ctx, userPasswordToken.GetUsername())
	if err != nil {
		return nil, err
	}

	userPassword, ok := u.(user.UserWithPassword)
	if !ok {
		return t, ErrUserTypeNotSupported
	}

	if err := o.userPasswordTokenChecker.CheckAuthentication(ctx, userPassword, userPasswordToken); err != nil {
		return nil, err
	}

	userPasswordToken.SetUser(userPassword)
	userPasswordToken.SetAuthenticated(true)
	return userPasswordToken, nil
}

func (o *UserPasswordAuthenticator) Support(ctx context.Context, t security.Token) bool {
	_, support := t.(user_password.TokenUserPassword)
	return support
}

func NewUserPasswordAuthenticator(provider security.UserProvider, checker user_password.TokenChecker) *UserPasswordAuthenticator {
	return &UserPasswordAuthenticator{
		userProvider:             provider,
		userPasswordTokenChecker: checker,
	}
}
