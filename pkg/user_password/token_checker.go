package user_password

import (
	"github.com/gol4ng/security/token"
)

type TokenChecker interface {
	CheckAuthentication(user UserPassword, t *token.UserPassword) error
}
