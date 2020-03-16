package token

type Anonymous struct {
	Base
	secret string
}

func NewAnonymous(secret string) *Anonymous {
	return &Anonymous{
		secret: secret,
	}
}
