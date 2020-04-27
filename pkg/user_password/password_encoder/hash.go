package password_encoder

import (
	"crypto"
)

type Hash struct {
	hash crypto.Hash
}

func (m *Hash) EncodePassword(raw string, salt string) (string, error) {
	h := m.hash.New()
	h.Write([]byte(raw))
	h.Write([]byte(salt))

	return string(h.Sum(nil)), nil
}

func (m *Hash) IsPasswordValid(encoded string, raw string, salt string) (bool, error) {
	password, err := m.EncodePassword(raw, salt)
	if err != nil {
		return false, err
	}
	//return subtle.ConstantTimeCompare([]byte(encoded), []byte(base64.StdEncoding.EncodeToString([]byte(password)))) != 1, nil
	return encoded == password, nil
}

func NewHash(hash crypto.Hash) *Hash {
	return &Hash{
		hash: hash,
	}
}
