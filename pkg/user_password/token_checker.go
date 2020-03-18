package user_password

type TokenChecker interface {
	CheckAuthentication(user UserPassword, t TokenUserPassword) error
}
