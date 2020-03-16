package token

import (
	"github.com/gol4ng/security"
)

type UserPassword struct {
	security.Token
	username string
	password string
}

func (u *UserPassword) GetUsername() string {
	return u.username
}

func (u *UserPassword) GetPassword() string {
	return u.password
}

func NewUserPassword(username string, password string) *UserPassword {
	return &UserPassword{
		Token:    &Base{},
		username: username,
		password: password,
	}
}
