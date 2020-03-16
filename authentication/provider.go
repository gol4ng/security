package authentication

import (
	"github.com/gol4ng/security"
)

type Provider interface {
	Authenticator
	Support(token security.Token) bool
}
