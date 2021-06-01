package security

import (
	"errors"
)

var (
	ErrTokenTypeNotSupported = errors.New("token type not supported")
	ErrUserNotFound = errors.New("user not found")
)

type AuthenticateError struct {
	message string
	cause   error
}

func (a *AuthenticateError) Error() string {
	err := a.message
	if a.cause != nil {
		err += ":" + a.cause.Error()
	}

	return err
}

func (a *AuthenticateError) Unwrap() error {
	return a.cause
}

func NewAuthenticateError(message string, err error) *AuthenticateError {
	return &AuthenticateError{
		message: message,
		cause:   err,
	}
}
