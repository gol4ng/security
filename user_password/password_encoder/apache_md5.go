package password_encoder

import (
	"context"

	"github.com/gol4ng/security/user_password/password_encoder/apache"
)

type ApacheMD5 struct{}

func (c *ApacheMD5) EncodePassword(_ context.Context, raw string, salt string) (string, error) {
	return string(apache.GenerateMD5FromPassword([]byte(raw), []byte(salt), []byte(apache.Magic))), nil
}

func (c *ApacheMD5) IsPasswordValid(_ context.Context, encoded string, raw string, salt string) (bool, error) {
	return apache.CompareMD5HashAndPassword([]byte(encoded), []byte(raw)) == nil, nil
}

func NewApacheMD5() *ApacheMD5 {
	return &ApacheMD5{}
}
