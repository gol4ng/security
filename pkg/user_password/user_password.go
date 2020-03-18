package user_password

import (
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/user"
)

type UserPassword interface {
	security.User
	GetPassword() string
	GetSalt() string
}

type User struct {
	security.User
	password string
	salt     string
}

func (u *User) GetPassword() string {
	return u.password
}

func (u *User) GetSalt() string {
	return u.salt
}

func NewUser(username string, password string, salt string) *User {
	return &User{
		User:     user.NewUser(username),
		password: password,
		salt:     salt,
	}
}
