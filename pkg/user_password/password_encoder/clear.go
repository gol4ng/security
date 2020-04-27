package password_encoder

type Clear struct {
}

func (c *Clear) EncodePassword(raw string, salt string) (string, error) {
	return raw, nil
}

func (c *Clear) IsPasswordValid(encoded string, raw string, salt string) (bool, error) {
	return encoded == raw, nil
}

func NewClear() *Clear {
	return &Clear{}
}
