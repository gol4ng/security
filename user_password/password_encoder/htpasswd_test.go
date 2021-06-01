package password_encoder_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/gol4ng/security/user_password/password_encoder"
	"github.com/stretchr/testify/assert"
)

func raw64Encode(data string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(data))
}

func Test_EncodePassword(t *testing.T) {
	tests := []struct {
		salt                string
		password            string
		encoded             string
		encodeErrorExpected string
	}{
		// MD5
		{password: "password1", encoded: "$apr1$$sDs.GdUFsGR.1BByyj3Wg0"},
		{password: "password11", salt: "fake_salt1", encoded: "$apr1$fake_salt1$eVrtTWJJmOmFPw683GUyP/"},
		// SHA1
		{password: "{SHA}password2", encoded: "{SHA}KqYKj/f81HPTIeAUav2eJt85UUc="},
		{password: "{SHA}password3", salt: "fake_salt", encoded: "{SHA}pTB4T3ba6LcyYrLOL6ZeXX9EMOA="},
		// Argon2 i, id, d
		{password: "$argon2i$v=19$m=16,t=2,p=1$" + raw64Encode("fake_salt") + "$" + raw64Encode("password4"), salt: "fake_salt", encoded: "$argon2i$v=19$m=16,t=2,p=1$ZmFrZV9zYWx0$d79wsFfJxfi0"},
		{password: "$argon2id$v=19$m=16,t=2,p=1$" + raw64Encode("fake_salt") + "$" + raw64Encode("password5"), salt: "fake_salt", encoded: "$argon2id$v=19$m=16,t=2,p=1$ZmFrZV9zYWx0$4KkeeGmeHkBm"},
		{password: "$argon2d$fake_unused_data", encodeErrorExpected: "Argon2d is not supported"},
	}

	htpasswd := password_encoder.NewHtpasswd()
	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			encoded, err := htpasswd.EncodePassword(tt.password, tt.salt)
			assert.Equal(t, tt.encoded, encoded)
			if tt.encodeErrorExpected != "" {
				assert.EqualError(t, err, tt.encodeErrorExpected)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// We can verify the hashed password only by compare to it because it internaly generate random byte
func Test_EncodePassword_Bcrypt(t *testing.T) {
	tests := []struct {
		rawPassword                string
		password                   string
		salt                       string
		encodeErrorExpected        string
		passwordValid              bool
		passwordValidErrorExpected string
	}{
		// Bcrypt
		{rawPassword: "password2", password: "$2a$password2", passwordValid: true},
		{rawPassword: "password2", password: "$2a$password2", salt: "fake_salt", passwordValid: true},
		{rawPassword: "password2", password: "$2b$password2", passwordValid: true},
		{rawPassword: "password2", password: "$2b$password2", salt: "fake_salt", passwordValid: true},
		{rawPassword: "password2", password: "$2x$password2", passwordValid: true},
		{rawPassword: "password2", password: "$2x$password2", salt: "fake_salt", passwordValid: true},
		{rawPassword: "password2", password: "$2y$password2", passwordValid: true},
		{rawPassword: "password2", password: "$2y$password2", salt: "fake_salt", passwordValid: true},
	}

	htpasswd := password_encoder.NewHtpasswd()
	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			encoded, err := htpasswd.EncodePassword(tt.password, tt.salt)
			fmt.Println(encoded)
			if tt.encodeErrorExpected != "" {
				assert.EqualError(t, err, tt.encodeErrorExpected)
			} else {
				assert.NoError(t, err)
			}
			isValid, err := htpasswd.IsPasswordValid(encoded, tt.rawPassword, tt.salt)
			assert.Equal(t, tt.passwordValid, isValid)
			if tt.passwordValidErrorExpected != "" {
				assert.EqualError(t, err, tt.passwordValidErrorExpected)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_IsPasswordValid(t *testing.T) {
	tests := []struct {
		rawPassword                string
		salt                       string
		encoded                    string
		passwordValid              bool
		passwordValidErrorExpected string
	}{
		// MD5
		{rawPassword: "password1", encoded: "$apr1$$sDs.GdUFsGR.1BByyj3Wg0", passwordValid: true},
		{rawPassword: "password11", salt: "fake_salt1", encoded: "$apr1$fake_salt1$eVrtTWJJmOmFPw683GUyP/", passwordValid: true},
		// SHA1
		{rawPassword: "password2", encoded: "{SHA}KqYKj/f81HPTIeAUav2eJt85UUc=", passwordValid: true},
		{rawPassword: "password3", salt: "fake_salt", encoded: "{SHA}pTB4T3ba6LcyYrLOL6ZeXX9EMOA=", passwordValid: true},
		// Bcrypt
		{rawPassword: "password2", encoded: "$2a$10$My/0E5TBWkrNNwUcBSPr1.W9qB9IxmhNHrp3yXpy5sI5vM9KTEb1W", passwordValid: true},
		{rawPassword: "password2", salt: "fake_salt", encoded: "$2a$10$sMmj4jicHVADvGLn6k2gSevkam5gI81tIGMJaGJ4tHGDoPUL.c0fC", passwordValid: true},
		{rawPassword: "password2", encoded: "$2a$10$xpLNZKDGReYF/Q3IWlceQOGchT3lgJ3GXNTwTKXzWpqELQ2Z6zOWi", passwordValid: true},
		{rawPassword: "password2", salt: "fake_salt", encoded: "$2a$10$4TTIRhH2I1aGHxQtBRGRYeocecshjqs1AecPC4bLc3a1x/A1nUaqO", passwordValid: true},
		{rawPassword: "password2", encoded: "$2a$10$vdRadM7r6.vE7kcOrLOYdu5ukgiqVepVNHq10L8S092AHL0aGy30m", passwordValid: true},
		{rawPassword: "password2", salt: "fake_salt", encoded: "$2a$10$XZXRxDpC4T5a4Lmk0udchO4zQOJrHFjyi3B26s2WBvANS1TCYf1bm", passwordValid: true},
		{rawPassword: "password2", encoded: "$2a$10$HL0ak1J.c9NRvg/0u5PsGuk1sIHiiBxMvQhkXwLvOMTVRmhQUNOG2", passwordValid: true},
		{rawPassword: "password2", salt: "fake_salt", encoded: "$2a$10$xnf3pqCUiExzd83iD/E3QuZYedQ423qy767Z7cHIz5xTyQ3hqaATm", passwordValid: true},
		// Argon2 i, id, d
		{rawPassword: "password4", salt: "fake_salt", encoded: "$argon2i$v=19$m=16,t=2,p=1$ZmFrZV9zYWx0$d79wsFfJxfi0", passwordValid: true},
		{rawPassword: "password5", salt: "fake_salt", encoded: "$argon2id$v=19$m=16,t=2,p=1$ZmFrZV9zYWx0$4KkeeGmeHkBm", passwordValid: true},
		{encoded: "$argon2d$fake_unused_data", passwordValidErrorExpected: "Argon2d is not supported", passwordValid: false},
	}

	htpasswd := password_encoder.NewHtpasswd()
	for _, tt := range tests {
		t.Run(tt.encoded, func(t *testing.T) {
			isValid, err := htpasswd.IsPasswordValid(tt.encoded, tt.rawPassword, tt.salt)
			assert.Equal(t, tt.passwordValid, isValid)
			if tt.passwordValidErrorExpected != "" {
				assert.EqualError(t, err, tt.passwordValidErrorExpected)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
