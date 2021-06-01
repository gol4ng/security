package main

import (
	"log"
	"net/http"

	security_http "github.com/gol4ng/security/pkg/http"
	middleware_http "github.com/gol4ng/security/pkg/http/middleware"
	"github.com/gol4ng/security/user_password/password_encoder"
	"github.com/gol4ng/security/user_password/token_checker"
	"github.com/gol4ng/security/user_provider"
)

// Run the program and
// browse http://localhost:8009/
// your browser will prompt you to enter user and password in order to access ressources
// it will respond 401 unhautorized if you try without or bad credentials
// Users available: (see .htpasswd)
// - "user1" password "user1" to test SHA1
// - "user2" password "user2" to test MD5
// - "user3" password "user3" to test Bcrypt
// - "user4" password "user4" to test Argon2
func main() {
	// Create a user provider (e.g htpasswd file)
	provider := user_provider.NewHtpasswd("./.htpasswd")

	// Create password encoder/decoder
	passwordEncoder := password_encoder.NewHtpasswd()

	// Create Basic authenticator
	secured := middleware_http.DefaultBasicAuthentication(
		provider,
		token_checker.NewUserPassword(passwordEncoder),
	)

	// Or you can create and change some options secured middleware
	//secured := middleware_http.Authentication(
	//	// Add Your basic auth
	//	authentication.NewBasicAuthenticator(
	//		provider,
	//		token_checker.NewUserPassword(passwordEncoder),
	//	),
	//	// Choose/implement your credential finder
	//	middleware.WithCredentialFinder(middleware_http.AuthorizationHeader),
	//	// Choose/implement your error handler (happen when 401 unhautenticate)
	//	middleware.WithErrorHandler(middleware_http.BasicErrorHandler("My restricted area", true)),
	//)

	// Use secured middleware to decorate your protected route
	http.Handle("/", secured(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		// You can get the authenticated token directly from the request context
		token := security_http.TokenFromContext(request.Context())
		responseWriter.Write([]byte("<h1>Access granted for <u>" + token.GetUser().GetUsername() + "</u></h1><br>You are allowed to access this protected content"))
	})))

	if err := http.ListenAndServe(":8009", nil); err != nil {
		log.Fatal(err)
	}
}
