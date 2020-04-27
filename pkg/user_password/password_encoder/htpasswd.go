package password_encoder

import (
	"errors"
	"strings"

	"github.com/gol4ng/security/pkg/user_password/password_encoder/apache"
	"github.com/gol4ng/security/pkg/user_password/password_encoder/argon2"
	"golang.org/x/crypto/bcrypt"
)

//https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
var errMismatchedHashAndPassword = errors.New("mismatched hash and password")

type Htpasswd struct {
}

func (c *Htpasswd) EncodePassword(raw string, salt string) (string, error) {
	return raw, nil
}

func (c *Htpasswd) IsPasswordValid(encoded string, raw string, salt string) (bool, error) {
	switch {
	// Command to generate
	// htpasswd -nbs my_username my_password
	case strings.HasPrefix(encoded, "{SHA}"):
		return apache.CompareSHA1HashAndPassword([]byte(encoded), []byte(raw)) == nil, nil
	// Bcrypt is complicated. According to crypt(3) from
	// crypt_blowfish version 1.3 (fetched from
	// http://www.openwall.com/crypt/crypt_blowfish-1.3.tar.gz), there
	// are three different has prefixes: "$2a$", used by versions up
	// to 1.0.4, and "$2x$" and "$2y$", used in all later
	// versions. "$2a$" has a known bug, "$2x$" was added as a
	// migration path for systems with "$2a$" prefix and still has a
	// bug, and only "$2y$" should be used by modern systems. The bug
	// has something to do with handling of 8-bit characters. Since
	// both "$2a$" and "$2x$" are deprecated, we are handling them the
	// same way as "$2y$", which will yield correct results for 7-bit
	// character passwords, but is wrong for 8-bit character
	// passwords. You have to upgrade to "$2y$" if you want sant 8-bit
	// character password support with bcrypt. To add to the mess,
	// OpenBSD 5.5. introduced "$2b$" prefix, which behaves exactly
	// like "$2y$" according to the same source.
	// Command to generate
	// htpasswd -nbB my_username my_password
	case strings.HasPrefix(encoded, "$2a$") ||
		strings.HasPrefix(encoded, "$2b$") ||
		strings.HasPrefix(encoded, "$2x$") ||
		strings.HasPrefix(encoded, "$2y$"):
		return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(raw)) == nil, nil

	// Argon2 is experimental
	// it require "golang.org/x/crypto/argon2"
	case strings.HasPrefix(encoded, "$argon2i$"):
		return argon2.CompareIPasswordAndHash([]byte(encoded), []byte(raw)) == nil, nil
	case strings.HasPrefix(encoded, "$argon2id$"):
		return argon2.CompareIDPasswordAndHash([]byte(encoded), []byte(raw)) == nil, nil

	// Command to generate
	// htpasswd -nbm my_username my_password
	// openssl passwd -apr1 my_password
	case strings.HasPrefix(encoded, ""):
		return apache.CompareMD5HashAndPassword([]byte(encoded), []byte(raw)) == nil, nil
	}

	return encoded == raw, nil
}

func NewHtpasswd() *Htpasswd {
	return &Htpasswd{}
}
