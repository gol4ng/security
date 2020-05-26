package token_checker

import (
	"context"
	"errors"
	"fmt"

	"github.com/gol4ng/security/user"
	"github.com/gol4ng/security/user_password"
)

var (
	ErrUsernameNotMatch = errors.New("username not match")
	ErrBadCredential    = errors.New("bad credential")
)

type UserPassword struct {
	encoder user_password.PasswordEncoder
}

func (u *UserPassword) CheckAuthentication(ctx context.Context, user user.UserWithPassword, t user_password.TokenUserPassword) error {
	if user.GetUsername() != t.GetUsername() {
		return ErrUsernameNotMatch
	}

	if isValid, err := u.encoder.IsPasswordValid(ctx, user.GetPassword(), t.GetPassword(), user.GetSalt()); err != nil {
		return fmt.Errorf("bad credential: %w", err)
	} else if !isValid {
		return ErrBadCredential
	}
	return nil
}

func NewUserPassword(encoder user_password.PasswordEncoder) *UserPassword {
	return &UserPassword{
		encoder: encoder,
	}
}
