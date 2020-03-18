package password_encoder

import (
	"crypto"
)

type Hash struct {
	hash crypto.Hash
}

func (m *Hash) EncodePassword(raw string, salt string) string {
	h := m.hash.New()
	h.Write([]byte(raw))
	h.Write([]byte(salt))

	return string(h.Sum(nil))
}

func (m *Hash) IsPasswordValid(encoded string, raw string, salt string) bool {
	return encoded == m.EncodePassword(raw, salt)
}

func NewHash(hash crypto.Hash) *Hash {
	return &Hash{
		hash: hash,
	}
}
