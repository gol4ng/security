package oauth2

import (
	security_token "github.com/gol4ng/security/token"
	"golang.org/x/oauth2"
)

type Token struct {
	security_token.Token

	oauth2Token *oauth2.Token
}

func (t *Token) GetToken() *oauth2.Token {
	return t.oauth2Token
}

func NewToken(oauth2Token *oauth2.Token) *Token {
	return &Token{
		oauth2Token: oauth2Token,
	}
}
