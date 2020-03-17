package token_checker

import (
	"errors"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type UserPassword struct {
	encoder security.PasswordEncoder
}

func (u *UserPassword) CheckAuthentication(user security.UserPassword, t *token.UserPassword) error {
	if user.GetUsername() != t.GetUsername() {
		return errors.New("username not match")
	}
	if !u.encoder.IsPasswordValid(user.GetPassword(), t.GetPassword(), user.GetSalt()) {
		return errors.New("bad credential")
	}
	return nil
}

func NewUserPassword(encoder security.PasswordEncoder) *UserPassword {
	return &UserPassword{
		encoder: encoder,
	}
}
