package password_encoder

import (
	"context"
	"errors"
	"strings"

	"github.com/gol4ng/security/user_password/password_encoder/apache"
	"github.com/gol4ng/security/user_password/password_encoder/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	prefixSHA      = "{SHA}"
	prefixBcrypt2a = "$2a$"
	prefixBcrypt2b = "$2b$"
	prefixBcrypt2x = "$2x$"
	prefixBcrypt2y = "$2y$"
	prefixArgon2i  = "$argon2i$"
	prefixArgon2d  = "$argon2d$"
	prefixArgon2id = "$argon2id$"
)

//https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
// TODO Split the different encoding in multiple files
type Htpasswd struct {
}

func (c *Htpasswd) EncodePassword(_ context.Context, raw string, salt string) (string, error) {
	switch {
	// Command to generate
	// htpasswd -nbs my_username my_password
	case strings.HasPrefix(raw, prefixSHA):
		return string(apache.GenerateSHA1FromPassword([]byte(strings.TrimPrefix(raw, prefixSHA) + salt))), nil
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
	case strings.HasPrefix(raw, prefixBcrypt2a):
		encoded, err := bcrypt.GenerateFromPassword([]byte(strings.TrimPrefix(raw, prefixBcrypt2a)), 1)
		return string(encoded), err
	case strings.HasPrefix(raw, prefixBcrypt2b):
		encoded, err := bcrypt.GenerateFromPassword([]byte(strings.TrimPrefix(raw, prefixBcrypt2b)), 1)
		return string(encoded), err
	case strings.HasPrefix(raw, prefixBcrypt2x):
		encoded, err := bcrypt.GenerateFromPassword([]byte(strings.TrimPrefix(raw, prefixBcrypt2x)), 1)
		return string(encoded), err
	case strings.HasPrefix(raw, prefixBcrypt2y):
		encoded, err := bcrypt.GenerateFromPassword([]byte(strings.TrimPrefix(raw, prefixBcrypt2y)), 1)
		return string(encoded), err
	// Argon2 is experimental
	// it require "golang.org/x/crypto/argon2"
	// https://argon2.online/
	case strings.HasPrefix(raw, prefixArgon2d):
		return "", errors.New("Argon2d is not supported")
	case strings.HasPrefix(raw, prefixArgon2i):
		p, providedSalt, clearPassword, err := argon2.DecodeHash(raw)
		if err != nil {
			return "", err
		}
		return argon2.GenerateIFromPassword(clearPassword, providedSalt, p)
	case strings.HasPrefix(raw, prefixArgon2id):
		p, providedSalt, clearPassword, err := argon2.DecodeHash(raw)
		if err != nil {
			return "", err
		}
		return argon2.GenerateIDFromPassword(clearPassword, providedSalt, p)
	// Command to generate
	// htpasswd -nbm my_username my_password
	// openssl passwd -apr1 my_password
	case strings.HasPrefix(raw, ""):
		return string(apache.GenerateMD5FromPassword([]byte(raw), []byte(salt), []byte(apache.Magic))), nil
	}

	return raw, nil
}

func (c *Htpasswd) IsPasswordValid(_ context.Context, encoded string, raw string, salt string) (bool, error) {
	switch {
	// Command to generate
	// htpasswd -nbs my_username my_password
	case strings.HasPrefix(encoded, prefixSHA):
		return apache.CompareSHA1HashAndPassword([]byte(encoded), []byte(raw+salt)) == nil, nil
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
	case strings.HasPrefix(encoded, prefixBcrypt2a) ||
		strings.HasPrefix(encoded, prefixBcrypt2b) ||
		strings.HasPrefix(encoded, prefixBcrypt2x) ||
		strings.HasPrefix(encoded, prefixBcrypt2y):
		return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(raw)) == nil, nil

	// Argon2 is experimental
	// it require "golang.org/x/crypto/argon2"
	case strings.HasPrefix(encoded, prefixArgon2d):
		return false, errors.New("Argon2d is not supported")
	case strings.HasPrefix(encoded, prefixArgon2i):
		return argon2.CompareIPasswordAndHash([]byte(encoded), []byte(raw)) == nil, nil
	case strings.HasPrefix(encoded, prefixArgon2id):
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
