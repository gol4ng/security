package password_encoder

import (
	"context"
)

type Digest struct {
}

func (c *Digest) EncodePassword(_ context.Context, raw string, salt string) (string, error) {
	//TODO
	return raw, nil
}

func (c *Digest) IsPasswordValid(_ context.Context, encoded string, raw string, salt string) (bool, error) {
	//TODO
	return encoded == raw, nil
}

func NewDigest() *Digest {
	return &Digest{}
}
