package user_password

import (
	"context"
)

type PasswordEncoder interface {
	EncodePassword(ctx context.Context, raw string, salt string) (string, error)
	IsPasswordValid(ctx context.Context, encoded string, raw string, salt string) (bool, error)
}
