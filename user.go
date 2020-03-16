package security

type User interface {
	GetUsername() string
	GetPassword() string
	GetSalt() string
}
