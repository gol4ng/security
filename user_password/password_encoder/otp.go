package password_encoder

import (
	"context"
)

type OTP struct {
}

func (c *OTP) EncodePassword(_ context.Context, raw string, salt string) (string, error) {
	//TODO
	return raw, nil
}

func (c *OTP) IsPasswordValid(_ context.Context, encoded string, raw string, salt string) (bool, error) {
	//TODO
	return encoded == raw, nil
}

func NewOTP() *OTP {
	return &OTP{}
}
