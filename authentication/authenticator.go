package authentication

import (
	"github.com/gol4ng/security"
)

type Authenticator interface {
	Authenticate(token security.Token) (security.Token, error)
}
