package password_encoder

type Digest struct {
}

func (c *Digest) EncodePassword(raw string, salt string) (string, error) {
	//TODO
	return raw, nil
}

func (c *Digest) IsPasswordValid(encoded string, raw string, salt string) (bool, error) {
	//TODO
	return encoded == raw, nil
}

func NewDigest() *Digest {
	return &Digest{}
}
