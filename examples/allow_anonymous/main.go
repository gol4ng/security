package main

import (
	"context"
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

func main() {
	ctx := context.Background()

	// Create a in memory user provider
	provider := user_provider.NewInMemory(map[string]security.User{
		"user1": user.NewUserPassword("user1", "user1password", ""),
		"user2": user.NewUser("user2"),
	})

	// Create password encoder/decoder
	passwordEncoder := password_encoder.NewClear()

	// Create a chain with anonymous authenticator
	chainAuthenticator := authentication.NewChainAuthenticator(
		authentication.NewAnonymousAuthenticator(),
		authentication.NewUserPasswordAuthenticator(
			provider,
			token_checker.NewUserPassword(passwordEncoder),
		),
	)

	// Try to authenticate user1
	t, err := chainAuthenticator.Authenticate(ctx, token.NewAnonymousToken())
	printResult(t, err)

	// Try to authenticate user1
	t, err = chainAuthenticator.Authenticate(ctx, user_password.NewToken("user1", "user1password"))
	printResult(t, err)

	// Failed to authenticate user2 (user2 in user provider is not supported by NewUserPasswordAuthenticator)
	t, err = chainAuthenticator.Authenticate(ctx, user_password.NewToken("user2", ""))
	printResult(t, err)

	// Failed to authenticate user3 (not exist)
	t, err = chainAuthenticator.Authenticate(ctx, user_password.NewToken("user3", "user3password"))
	printResult(t, err)

	// Failed to authenticate user1 (bad password)
	t, err = chainAuthenticator.Authenticate(ctx, user_password.NewToken("user1", "BAD_PASSWORD"))
	printResult(t, err)
}

func printResult(token security.Token, err error) {
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return
	}
	u := token.GetUser()
	if u != nil {
		fmt.Printf("User \"%s\" successfully authenticated\n", token.GetUser().GetUsername())
		return
	}
	fmt.Println("Anonymous user successfully authenticated")
}
