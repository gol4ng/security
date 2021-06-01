package security

import (
	"context"
)

type Authenticator interface {
	Authenticate(ctx context.Context, token Token) (Token, error)
	Support(ctx context.Context, token Token) bool
}
