package jwt

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

type Parser interface {
	Parse(token string) (*jwt.Token, error)
}

type ParserWithPublicKey struct {
	signingKeys          map[string]interface{}
	validMethods         []string
	UseJSONNumber        bool
	SkipClaimsValidation bool
}

type Option func(*ParserWithPublicKey)

func NewParser(options ...Option) Parser {
	parser := &ParserWithPublicKey{
		signingKeys:  map[string]interface{}{},
		validMethods: []string{},
	}
	for _, o := range options {
		o(parser)
	}
	return parser
}

func (p ParserWithPublicKey) Parse(token string) (*jwt.Token, error) {
	parser := jwt.Parser{
		ValidMethods:         p.validMethods,
		UseJSONNumber:        p.UseJSONNumber,
		SkipClaimsValidation: p.SkipClaimsValidation,
	}

	return parser.Parse(token, p.keyFunc)
}

func (p ParserWithPublicKey) keyFunc(token *jwt.Token) (interface{}, error) {
	alg := token.Method.Alg()
	key, ok := p.signingKeys[alg]
	if !ok {
		return nil, errors.New("algo not found")
	}
	return key, nil
}

func WithSigningKey(name string, key interface{}) Option {
	return func(parser *ParserWithPublicKey) {
		if _, ok := parser.signingKeys[name]; !ok {
			parser.signingKeys[name] = key
			parser.validMethods = append(parser.validMethods, name)
		}
	}
}

func UseJSONNumber(useJSONNumber bool) Option {
	return func(parser *ParserWithPublicKey) {
		parser.UseJSONNumber = useJSONNumber
	}
}

func SkipClaimsValidation(skipClaimsValidation bool) Option {
	return func(parser *ParserWithPublicKey) {
		parser.SkipClaimsValidation = skipClaimsValidation
	}
}
