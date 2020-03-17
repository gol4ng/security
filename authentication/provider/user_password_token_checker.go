package provider

import (
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type UserPasswordTokenChecker interface {
	CheckAuthentication(user security.UserPassword, t *token.UserPassword) error
}
