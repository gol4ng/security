package password_encoder

import (
	"context"
	"crypto"
)

type Hash struct {
	hash crypto.Hash
}

func (m *Hash) EncodePassword(_ context.Context, raw string, salt string) (string, error) {
	h := m.hash.New()
	h.Write([]byte(raw))
	h.Write([]byte(salt))

	return string(h.Sum(nil)), nil
}

func (m *Hash) IsPasswordValid(ctx context.Context, encoded string, raw string, salt string) (bool, error) {
	password, err := m.EncodePassword(ctx, raw, salt)
	if err != nil {
		return false, err
	}
	//return subtle.ConstantTimeCompare([]byte(encoded), []byte(base64.StdEncoding.EncodeToString([]byte(password)))) != 1, nil // TODO DOUBLE CHECK
	return encoded == password, nil
}

func NewHash(hash crypto.Hash) *Hash {
	return &Hash{
		hash: hash,
	}
}
