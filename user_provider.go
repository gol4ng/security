package security

import (
	"context"
)

type UserProvider interface {
	LoadUserByUsername(ctx context.Context, username string) (User, error)
}
