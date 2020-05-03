package password_encoder

import (
	"golang.org/x/crypto/bcrypt"
)

type Bcrypt struct {
	cost int
}

func (c *Bcrypt) EncodePassword(raw string, salt string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(raw+salt), c.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (c *Bcrypt) IsPasswordValid(encoded string, raw string, salt string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(raw), []byte(raw+salt))
	return err == nil, err
}

func NewBcrypt(cost int) *Bcrypt {
	return &Bcrypt{cost: cost}
}
