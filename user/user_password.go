package user

import (
	"github.com/gol4ng/security"
)

type UserWithPassword interface {
	security.User
	GetPassword() string
	GetSalt() string
}

type UserPassword struct {
	security.User
	password string
	salt     string
}

func (u *UserPassword) GetPassword() string {
	return u.password
}

func (u *UserPassword) GetSalt() string {
	return u.salt
}

func NewUserPassword(username string, password string, salt string) *UserPassword {
	return &UserPassword{
		User:     NewUser(username),
		password: password,
		salt:     salt,
	}
}
