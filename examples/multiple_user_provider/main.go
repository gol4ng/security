package main

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/authentication"
	"github.com/gol4ng/security/token"
	"github.com/gol4ng/security/user"
	"github.com/gol4ng/security/user_password"
	"github.com/gol4ng/security/user_password/password_encoder"
	"github.com/gol4ng/security/user_password/token_checker"
	"github.com/gol4ng/security/user_provider"
)

// Run the program in this directory (or move the .htpasswd in the correct folder)
// Users available: (see .htpasswd)
// - "user1" password "user1password" to test MD5
// - "user2" password "user2password" to test SHA1
// - "user3" password "user3password" to test Bcrypt
// - "user4" password "user4password" to test Argon2
func main() {
	ctx := context.Background()

	// Create a user provider (e.g htpasswd file)
	provider := user_provider.NewHtpasswd("./.htpasswd")
	// Create password encoder/decoder
	passwordEncoder := password_encoder.NewHtpasswd()

	inMemoryProvider := user_provider.NewInMemory(map[string]security.User{
		"other_user1": user.NewUserPassword("other_user1", "other_user1password", ""),
	})

	// Create a chain authenticator
	basicAuthenticator := authentication.NewChainAuthenticator(
		authentication.NewBasicAuthenticator(
			provider,
			token_checker.NewUserPassword(passwordEncoder),
		),
		authentication.NewUserPasswordAuthenticator(
			inMemoryProvider,
			token_checker.NewUserPassword(password_encoder.NewClear()),
		),
	)

	// Try to authenticate user1 with MD5 password
	t, err := basicAuthenticator.Authenticate(ctx, token.NewRawToken(basicUserPassword("user1", "user1password")))
	printResult(t, err)

	// Try to authenticate user2 with SHA1 password
	t, err = basicAuthenticator.Authenticate(ctx, token.NewRawToken(basicUserPassword("user2", "user2password")))
	printResult(t, err)

	// Try to authenticate user3 with Bcrypt password
	t, err = basicAuthenticator.Authenticate(ctx, token.NewRawToken(basicUserPassword("user3", "user3password")))
	printResult(t, err)

	// Try to authenticate user4 with argon2 password
	t, err = basicAuthenticator.Authenticate(ctx, token.NewRawToken(basicUserPassword("user4", "user4password")))
	printResult(t, err)

	// Failed to authenticate user5 (not exist)
	t, err = basicAuthenticator.Authenticate(ctx, token.NewRawToken(basicUserPassword("user5", "user5password")))
	printResult(t, err)

	// Failed to authenticate user1 (bad password)
	t, err = basicAuthenticator.Authenticate(ctx, token.NewRawToken(basicUserPassword("user1", "BAD_PASSWORD")))
	printResult(t, err)

	// Authenticate other_user1 (second user provider)
	t, err = basicAuthenticator.Authenticate(ctx, user_password.NewToken("other_user1", "other_user1password"))
	printResult(t, err)
}

func basicUserPassword(user string, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}

func printResult(token security.Token, err error) {
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return
	}
	fmt.Printf("User \"%s\" successfully authenticated\n", token.GetUser().GetUsername())
}
