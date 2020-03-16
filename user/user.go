package user

type User struct {
	username string
}

func (u *User) GetUsername() string {
	return u.username
}
