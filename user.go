package security

type User interface {
	GetUsername() string
}

type UserPassword interface {
	User
	GetPassword() string
	GetSalt() string
}
