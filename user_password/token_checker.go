package user_password

import (
	"github.com/gol4ng/security/user"
)

type TokenChecker interface {
	CheckAuthentication(user user.UserWithPassword, t TokenUserPassword) error
}
