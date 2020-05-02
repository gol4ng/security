package user_provider

import (
	"github.com/gol4ng/security"
	"github.com/gol4ng/security/pkg/user_password"
	"github.com/gol4ng/security/user_provider/file"
)

type Htpasswd struct {
	filename string
	file     *file.Htpasswd
}

func (i *Htpasswd) LoadUserByUsername(username string) (security.User, error) {
	if i.file == nil {
		var err error
		i.file, err = file.OpenHtpasswd(i.filename)
		if err != nil {
			return nil, err
		}
	}
	users, err := i.file.GetUsers()
	if err != nil {
		return nil, err
	}
	if password, ok := users[username]; ok {
		return user_password.NewUser(username, password, ""), nil
	}
	return nil, security.ErrUserNotFound
}

func NewHtpasswd(filename string) *Htpasswd {
	return &Htpasswd{
		filename: filename,
	}
}
