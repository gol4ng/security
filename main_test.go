package security_test

import (
	"crypto"
	_ "crypto/md5"
	"testing"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/authentication"
	"github.com/gol4ng/security/authentication/provider"
	"github.com/gol4ng/security/authentication/provider/token_checker"
	"github.com/gol4ng/security/password_encoder"
	"github.com/gol4ng/security/token"
	"github.com/gol4ng/security/user"
	"github.com/gol4ng/security/user_provider"
	"github.com/stretchr/testify/assert"
)

func getAuthenticator() authentication.Authenticator {
	encoder := password_encoder.NewHash(crypto.MD5)
	userPasswordTokenChecker := token_checker.NewUserPassword(encoder)

	salt := "kLmqshuNoxal"
	userProvider := user_provider.NewInMemory(map[string]security.User{
		"james": user.NewUserPassword("james", encoder.EncodePassword("bond", salt), salt),
	})

	return authentication.NewChainAuthenticator(
		&provider.AnonymousAccess{},
		provider.NewUserPassword(userProvider, userPasswordTokenChecker),
	)
}

func Test_AnonymousLogin(t *testing.T) {
	userToken := token.NewAnonymous("fake_secret")
	authToken, err := getAuthenticator().Authenticate(userToken)

	assert.True(t, authToken.IsAuthenticated())
	assert.NoError(t, err)
}

func Test_UserPasswordLogin(t *testing.T) {
	t.Run("User login", func(t *testing.T) {
		userToken := token.NewUserPassword("james", "bond")
		authToken, err := getAuthenticator().Authenticate(userToken)

		assert.True(t, authToken.IsAuthenticated())
		assert.NoError(t, err)
	})

	t.Run("User login with wrong credential", func(t *testing.T) {
		userToken := token.NewUserPassword("james", "bad_password")
		authToken, err := getAuthenticator().Authenticate(userToken)
		assert.Nil(t, authToken)
		assert.EqualError(t, err, "bad credential")
	})
}
