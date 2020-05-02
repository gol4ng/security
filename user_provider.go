package security

type UserProvider interface {
	LoadUserByUsername(username string) (User, error)
}
