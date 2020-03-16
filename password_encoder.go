package security

type PasswordEncoder interface {
	EncodePassword(raw string, salt string) string
	IsPasswordValid(encoded string, raw string, salt string) bool
}
