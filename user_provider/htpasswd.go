package user_provider

import (
	"context"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/user"
	"github.com/gol4ng/security/user_provider/file"
)

type Htpasswd struct {
	filename string
	file     *file.Htpasswd
}

func (i *Htpasswd) Load() error {
	var err error
	i.file, err = file.OpenHtpasswd(i.filename)
	if err != nil {
		return err
	}
	return nil
}

func (i *Htpasswd) LoadUserByUsername(_ context.Context, username string) (security.User, error) {
	if i.file == nil {
		if err := i.Load(); err != nil {
			return nil, err
		}
	}
	users, err := i.file.GetUsers()
	if err != nil {
		return nil, err
	}
	if password, ok := users[username]; ok {
		return user.NewUserPassword(username, password, ""), nil
	}
	return nil, security.ErrUserNotFound
}

func NewHtpasswd(filename string) *Htpasswd {
	return &Htpasswd{
		filename: filename,
	}
}
