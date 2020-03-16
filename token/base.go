package token

import (
	"github.com/gol4ng/security"
)

type Base struct {
	user          security.User
	authenticated bool
}

func (a *Base) SetAuthenticated(authenticated bool) {
	a.authenticated = authenticated
}

func (a *Base) IsAuthenticated() bool {
	return a.authenticated
}

func (a *Base) SetUser(user security.User) {
	a.user = user
}

func (a *Base) GetUser() security.User {
	return a.user
}
