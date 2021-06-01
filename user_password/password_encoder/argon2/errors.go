package argon2

import (
	"errors"
)

var (
	ErrMismatchedHashAndPassword = errors.New("mismatched hash and password")
	ErrInvalidHash               = errors.New("the encoded hash is not in the correct format")
)
