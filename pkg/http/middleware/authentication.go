package middleware

import (
	"github.com/gol4ng/httpware/v4"
	"github.com/gol4ng/httpware/v4/middleware"
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/authentication"
	authentication_http "github.com/gol4ng/security/pkg/http/authentication"
	"github.com/gol4ng/security/user_password"
)

const DefaultRealm = "Restricted area"

func DefaultBasicAuthentication(provider security.UserProvider, checker user_password.TokenChecker) httpware.Middleware {
	return middleware.Authentication(
		middleware.NewAuthenticateFunc(
			authentication_http.NewAuthenticatorAdapter(authentication.NewBasicAuthenticator(provider, checker)),
			middleware.WithCredentialFinder(AuthorizationHeader),
		),
		middleware.WithErrorHandler(BasicErrorHandler(DefaultRealm, false)),
	)
}
