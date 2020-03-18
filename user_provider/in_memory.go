package user_provider

import (
	"errors"

	"github.com/gol4ng/security"
)

type InMemory struct {
	users map[string]security.User
}

func (i *InMemory) LoadUserByUsername(username string) (security.User, error) {
	if u, ok := i.users[username]; ok {
		return u, nil
	}
	return nil, errors.New("user not found")
}

func (i *InMemory) RefreshUser(user security.User) error {
	return nil
}

func (i *InMemory) SupportsClass(user security.User) bool {
	return true
}

func NewInMemory(users map[string]security.User) *InMemory {
	return &InMemory{users: users}
}
