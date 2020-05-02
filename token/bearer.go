package token

import (
	"github.com/gol4ng/security"
)

type BearerToken struct {
	security.Token

	raw string
}

