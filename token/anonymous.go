package token

import (
	"github.com/gol4ng/security"
)

type Anonymous struct {
	security.Token
}

func NewToken() *Anonymous {
	return &Anonymous{
		Token: &Anonymous{},
	}
}
