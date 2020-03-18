package password_encoder

import (
	"reflect"

	"github.com/gol4ng/security"
	"github.com/gol4ng/security/pkg/user_password"
)

type Factory struct {
	encoders map[reflect.Type]user_password.PasswordEncoder
}

func (f *Factory) GetEncoder(user security.User) user_password.PasswordEncoder {
	if e, ok := f.encoders[reflect.TypeOf(user)]; ok {
		return e
	}
	return nil
}
