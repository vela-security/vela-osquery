package osquery

import (
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
)

type row map[string]string

func (r row) Type() lua.LValueType                   { return lua.LTObject }
func (r row) AssertFloat64() (float64, bool)         { return 0, false }
func (r row) AssertString() (string, bool)           { return "", false }
func (r row) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (r row) Peek() lua.LValue                       { return r }

func (r row) String() string {
	buff := kind.NewJsonEncoder()

	buff.Tab("")
	for key, val := range r {
		buff.KV(key, val)
	}
	buff.End("},")

	return lua.B2S(buff.Bytes())
}

func (r row) Index(L *lua.LState, key string) lua.LValue {
	if r == nil {
		return lua.LNil
	}

	item, ok := r[key]
	if !ok {
		return lua.LNil
	}

	return lua.S2L(item)
}
