package token_checker

import (
	"errors"

	"github.com/gol4ng/security/pkg/user_password"
)

type UserPassword struct {
	encoder user_password.PasswordEncoder
}

func (u *UserPassword) CheckAuthentication(user user_password.UserPassword, t user_password.TokenUserPassword) error {
	if user.GetUsername() != t.GetUsername() {
		return errors.New("username not match")
	}
	if !u.encoder.IsPasswordValid(user.GetPassword(), t.GetPassword(), user.GetSalt()) {
		return errors.New("bad credential")
	}
	return nil
}

func NewUserPassword(encoder user_password.PasswordEncoder) *UserPassword {
	return &UserPassword{
		encoder: encoder,
	}
}
