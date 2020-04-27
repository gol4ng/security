package token

type RawToken struct {
	Token

	raw string
}

func (b *RawToken) GetRaw() string {
	return b.raw
}

func NewRawToken(raw string) *RawToken {
	return &RawToken{
		Token: Token{},
		raw:   raw,
	}
}
