package user_password

import (
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type TokenUserPassword interface {
	security.Token
	GetUsername() string
	GetPassword() string
}

type Token struct {
	security.Token
	username string
	password string
}

func (u *Token) GetUsername() string {
	return u.username
}

func (u *Token) GetPassword() string {
	return u.password
}

func NewToken(username string, password string) *Token {
	return &Token{
		Token:    &token.Token{},
		username: username,
		password: password,
	}
}
