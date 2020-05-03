package apache

import (
	"errors"
)

var (
	ErrMismatchedHashAndPassword = errors.New("mismatched hash and password")
)
