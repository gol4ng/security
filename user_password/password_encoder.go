package user_password

type PasswordEncoder interface {
	EncodePassword(raw string, salt string) (string, error)
	IsPasswordValid(encoded string, raw string, salt string) (bool, error)
}
