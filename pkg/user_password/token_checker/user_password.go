package token_checker

import (
	"errors"
	"fmt"

	"github.com/gol4ng/security/pkg/user_password"
)

type UserPassword struct {
	encoder user_password.PasswordEncoder
}

func (u *UserPassword) CheckAuthentication(user user_password.UserPassword, t user_password.TokenUserPassword) error {
	if user.GetUsername() != t.GetUsername() {
		return errors.New("username not match")
	}

	if isValid, err := u.encoder.IsPasswordValid(user.GetPassword(), t.GetPassword(), user.GetSalt()); err != nil {
		return fmt.Errorf("bad credential: %w", err)
	} else if !isValid {
		return errors.New("bad credential")
	}
	return nil
}

func NewUserPassword(encoder user_password.PasswordEncoder) *UserPassword {
	return &UserPassword{
		encoder: encoder,
	}
}
