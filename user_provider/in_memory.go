package user_provider

import (
	"errors"

	"github.com/gol4ng/security"
)

type InMemory struct {
	users map[string]security.User
}

func (p *InMemory) LoadUserByUsername(username string) (security.User, error) {
	if u, ok := p.users[username]; ok {
		return u, nil
	}
	return nil, errors.New("user not found")
}

func (p *InMemory) RefreshUser(user security.User) error {
	return nil
}

func (p *InMemory) SupportsClass(user security.User) bool {
	return true
}

func NewInMemory(users map[string]security.User) *InMemory {
	return &InMemory{users: users}
}
