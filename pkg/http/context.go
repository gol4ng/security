package security_http

import (
	"context"

	"github.com/gol4ng/httpware/v4/auth"
	"github.com/gol4ng/security"
)

func TokenFromContext(ctx context.Context) security.Token {
	if ctx == nil {
		return nil
	}
	value := auth.CredentialFromContext(ctx)
	if token, ok := value.(security.Token); ok {
		return token
	}
	return nil
}
