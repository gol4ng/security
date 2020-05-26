package middleware

import (
	"net/http"
	"strings"

	"github.com/gol4ng/httpware/v4/auth"
	"github.com/gol4ng/security/token"
)

func AuthorizationHeader(request *http.Request) auth.Credential {
	authHeader := getAuthorizationHeader(request)
	switch {
	case strings.HasPrefix(authHeader, "Basic "):
		return token.NewRawToken(strings.TrimLeft(authHeader, "Basic "))
	case strings.HasPrefix(authHeader, "Bearer "):
		return token.NewRawToken(strings.TrimLeft(authHeader, "Bearer "))
	}

	return token.NewRawToken(authHeader)
}

func getAuthorizationHeader(request *http.Request) string {
	if request == nil {
		return ""
	}

	authHeader := request.Header.Get(auth.AuthorizationHeader)
	if authHeader == "" {
		authHeader = request.Header.Get(auth.XAuthorizationHeader)
	}
	return authHeader
}
