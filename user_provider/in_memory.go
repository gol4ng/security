package user_provider

import (
	"context"

	"github.com/gol4ng/security"
)

type InMemory struct {
	users map[string]security.User
}

func (i *InMemory) LoadUserByUsername(_ context.Context, username string) (security.User, error) {
	if u, ok := i.users[username]; ok {
		return u, nil
	}
	return nil, security.ErrUserNotFound
}

func NewInMemory(users map[string]security.User) *InMemory {
	return &InMemory{users: users}
}
