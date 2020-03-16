package user

type UserPassword struct {
	User
	password string
	salt     string
}

func (u *UserPassword) GetPassword() string {
	return u.password
}

func (u *UserPassword) GetSalt() string {
	return u.salt
}

func NewUserPassword(username string, password string, salt string) *UserPassword {
	return &UserPassword{
		User:     User{username: username},
		password: password,
		salt:     salt,
	}
}
