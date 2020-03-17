package security

type UserProvider interface {
	LoadUserByUsername(username string) (User, error)
	//RefreshUser(user *User) error
	//SupportsClass(user *User) bool
}
