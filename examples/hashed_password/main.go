package main

import (
	"context"
	"crypto"
	_ "crypto/sha512"
	"fmt"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/authentication"
	"github.com/gol4ng/security/user"
	"github.com/gol4ng/security/user_password"
	"github.com/gol4ng/security/user_password/password_encoder"
	"github.com/gol4ng/security/user_password/token_checker"
	"github.com/gol4ng/security/user_provider"
)

func main() {
	ctx := context.Background()

	// Create password encoder/decoder
	// dont forget to import the appropriate package for hash function
	// import _ "crypto/sha512"
	// refer to @https://golang.org/src/crypto/crypto.go
	passwordEncoder := password_encoder.NewHash(crypto.SHA512)

	// Create a in memory user provider
	provider := user_provider.NewInMemory(map[string]security.User{
		"user1": user.NewUserPassword("user1", mustEncodePassword(passwordEncoder, "user1password", "user1Salt"), "user1Salt"),
		"user2": user.NewUser("user2"),
	})

	// Create a user password authenticator
	basicAuthenticator := authentication.NewUserPasswordAuthenticator(
		provider,
		token_checker.NewUserPassword(passwordEncoder),
	)

	// Try to authenticate user1
	t, err := basicAuthenticator.Authenticate(ctx, user_password.NewToken("user1", "user1password"))
	printResult(t, err)

	// Failed to authenticate user2 (user2 in user provider is not supported by NewUserPasswordAuthenticator)
	t, err = basicAuthenticator.Authenticate(ctx, user_password.NewToken("user2", ""))
	printResult(t, err)

	// Failed to authenticate user3 (not exist)
	t, err = basicAuthenticator.Authenticate(ctx, user_password.NewToken("user3", "user3password"))
	printResult(t, err)

	// Failed to authenticate user1 (bad password)
	t, err = basicAuthenticator.Authenticate(ctx, user_password.NewToken("user1", "BAD_PASSWORD"))
	printResult(t, err)
}

func mustEncodePassword(passwordEncoder user_password.PasswordEncoder, password string, salt string) string {
	encoded, err := passwordEncoder.EncodePassword(password, salt)
	if err != nil {
		panic(err)
	}
	return encoded
}

func printResult(token security.Token, err error) {
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return
	}
	fmt.Printf("User \"%s\" successfully authenticated\n", token.GetUser().GetUsername())
}
