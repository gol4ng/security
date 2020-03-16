package password_encoder

import (
	"reflect"

	"github.com/gol4ng/security"
)

type Factory struct {
	encoders map[reflect.Type]security.PasswordEncoder
}

func (f *Factory) GetEncoder(user security.User) security.PasswordEncoder {
	if e, ok := f.encoders[reflect.TypeOf(user)]; ok {
		return e
	}
	return nil
}
