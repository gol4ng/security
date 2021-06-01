package user

type User struct {
	username string
}

func (u *User) GetUsername() string {
	return u.username
}

func NewUser(username string) *User {
	return &User{username}
}
