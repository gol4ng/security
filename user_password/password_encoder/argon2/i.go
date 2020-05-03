package argon2

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/gol4ng/security/user_password/password_encoder"
	"golang.org/x/crypto/argon2"
)

func GenerateIFromPassword(password []byte, p *params) (encodedHash string, err error) {
	// Generate a cryptographically secure random salt.
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	// Pass the plaintext password, salt and parameters to the argon2.Key
	// function. This will generate a hash of the password using the Argon2i
	// variant.
	hash := argon2.Key(password, salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string using the standard encoded hash representation.
	encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func CompareIPasswordAndHash(hashedPassword []byte, password []byte) error {
	p, salt, hash, err := decodeHash(string(hashedPassword))
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(hash, argon2.Key(password, salt, p.iterations, p.memory, p.parallelism, p.keyLength)) != 1 {
		return password_encoder.ErrMismatchedHashAndPassword
	}
	return nil
}
