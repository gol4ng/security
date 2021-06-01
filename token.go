package security

type Token interface {
	SetUser(User)
	GetUser() User
	SetAuthenticated(bool)
	IsAuthenticated() bool
}
