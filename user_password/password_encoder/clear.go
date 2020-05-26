package password_encoder

import (
	"context"
)

type Clear struct {
}

func (c *Clear) EncodePassword(_ context.Context, raw string, salt string) (string, error) {
	return raw, nil
}

func (c *Clear) IsPasswordValid(_ context.Context, encoded string, raw string, salt string) (bool, error) {
	return encoded == raw, nil
}

func NewClear() *Clear {
	return &Clear{}
}
