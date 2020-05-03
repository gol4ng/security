package apache

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"

	"github.com/gol4ng/security/user_password/password_encoder"
)

func GenerateSHA1FromPassword(password []byte) []byte {
	d := sha1.New()
	d.Write(password)
	return append([]byte("{SHA}"), []byte(base64.StdEncoding.EncodeToString(d.Sum(nil)))...)
}

func CompareSHA1HashAndPassword(hashedPassword []byte, password []byte) error {
	if subtle.ConstantTimeCompare(hashedPassword, GenerateSHA1FromPassword(password)) != 1 {
		return password_encoder.ErrMismatchedHashAndPassword
	}
	return nil
}
