package user_password

import (
	"context"

	"github.com/gol4ng/security/user"
)

type TokenChecker interface {
	CheckAuthentication(ctx context.Context, user user.UserWithPassword, t TokenUserPassword) error
}
