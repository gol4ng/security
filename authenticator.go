package security

type Authenticator interface {
	Authenticate(token Token) (Token, error)
	Support(token Token) bool
}
