package password_encoder

type OTP struct {
}

func (c *OTP) EncodePassword(raw string, salt string) (string, error) {
	return raw, nil
}

func (c *OTP) IsPasswordValid(encoded string, raw string, salt string) (bool, error) {
	return encoded == raw, nil
}

func NewOTP() *OTP {
	return &OTP{}
}
