package authentication

import (
	"encoding/base64"
	"errors"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/token"
)

type TokenTransformer func(rawToken *token.RawToken) (*token.RawToken, error)

type RawAuthenticatorWrapper struct {
	authenticator    security.Authenticator
	tokenTransformer TokenTransformer
}

func (r *RawAuthenticatorWrapper) Authenticate(t security.Token) (security.Token, error) {
	rawToken, ok := t.(*token.RawToken)
	if !ok {
		return t, errors.New("token type not supported")
	}

	newToken, err := r.tokenTransformer(rawToken)
	if err != nil {
		return t, err
	}

	return r.authenticator.Authenticate(newToken)
}

func (r *RawAuthenticatorWrapper) Support(t security.Token) bool {
	_, support := t.(*token.RawToken)
	return support
}

func (r *RawAuthenticatorWrapper) apply(options ...AuthenticatorOption) *RawAuthenticatorWrapper {
	for _, option := range options {
		option(r)
	}
	return r
}

type AuthenticatorOption func(*RawAuthenticatorWrapper)

func NewRawAuthenticatorWrapper(authenticator security.Authenticator, options ...AuthenticatorOption) *RawAuthenticatorWrapper {
	wrapper := &RawAuthenticatorWrapper{
		authenticator:    authenticator,
		tokenTransformer: RawTokenBase64Decode,
	}

	return wrapper.apply(options...)
}

func WithTokenTransformer(transformer TokenTransformer) AuthenticatorOption {
	return func(authenticator *RawAuthenticatorWrapper) {
		authenticator.tokenTransformer = transformer
	}
}

func RawTokenBase64Decode(rawToken *token.RawToken) (*token.RawToken, error) {
	decoded, err := base64.StdEncoding.DecodeString(rawToken.GetRaw())
	if err != nil {
		return rawToken, err
	}
	return token.NewRawToken(string(decoded)), nil
}
