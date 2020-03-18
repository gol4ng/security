package token

import (
	"github.com/gol4ng/security"
)

type Token struct {
	user          security.User
	authenticated bool
}

func (t *Token) SetAuthenticated(authenticated bool) {
	t.authenticated = authenticated
}

func (t *Token) IsAuthenticated() bool {
	return t.authenticated
}

func (t *Token) SetUser(user security.User) {
	t.user = user
}

func (t *Token) GetUser() security.User {
	return t.user
}
