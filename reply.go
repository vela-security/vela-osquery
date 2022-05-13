package osquery

import (
	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

type reply struct {
	Status *osquery.ExtensionStatus
	Body   []map[string]string
	Err    error
}

func newReply(r *osquery.ExtensionResponse, e error) reply {
	var ret reply
	if r == nil {
		ret.Err = e
		return ret
	}

	return reply{
		Status: r.Status,
		Body:   r.Response,
		Err:    e,
	}
}

func (r reply) String() string                         { return lua.B2S(r.raw()) }
func (r reply) Type() lua.LValueType                   { return lua.LTObject }
func (r reply) AssertFloat64() (float64, bool)         { return 0, false }
func (r reply) AssertString() (string, bool)           { return "", false }
func (r reply) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (r reply) Peek() lua.LValue                       { return r }

func (r reply) Meta(L *lua.LState, key lua.LValue) lua.LValue {
	n, ok := key.AssertFloat64()
	if !ok {
		return lua.LNil
	}

	idx := int(n)
	if idx >= len(r.Body) {
		return lua.LNil
	}

	return row(r.Body[idx])
}

func (r reply) Index(L *lua.LState, key string) lua.LValue {
	switch key {

	case "ok":
		return lua.LBool(r.ok())

	case "msg":
		if r.ok() {
			return lua.S2L(r.Status.Message)
		}
	case "raw":
		if r.ok() {
			return lua.B2L(r.raw())
		}

	case "code":
		if r.ok() {
			return lua.LInt(r.Status.Code)
		}
	case "count":
		if r.ok() {
			return lua.LInt(len(r.Body))
		}
		return lua.LInt(0)

	case "uuid":
		if r.ok() {
			return lua.LNumber(r.Status.UUID)
		}

	case "error":
		if !r.ok() {
			return lua.S2L(r.Err.Error())
		}

	case "pipe":
		return L.NewFunction(r.pipeL)

	}

	return lua.LNil
}

func (r *reply) ok() bool {
	if r.Err == nil {
		return true
	}
	return false
}

func (r *reply) pipeL(L *lua.LState) int {
	if !r.ok() {
		return 0
	}

	n := len(r.Body)
	if n == 0 {
		return 0
	}
	pp := pipe.New()
	pp.CheckMany(L, pipe.Seek(0))
	if pp.Len() == 0 {
		return 0
	}

	for i := 0; i < n; i++ {
		pp.Do(row(r.Body[i]), L, func(err error) {
			xEnv.Errorf("%s pipe %v", err)
		})
	}
	return 0
}

var null = []byte("[]")

func (r *reply) raw() []byte {
	if !r.ok() {
		return null
	}

	n := len(r.Body)
	if n == 0 {
		return null
	}

	buffer := kind.NewJsonEncoder()
	buffer.Arr("")
	for i := 0; i < n; i++ {
		buffer.Tab("")
		for key, val := range r.Body[i] {
			buffer.KV(key, val)
		}
		buffer.End("},")
	}
	buffer.End("]")

	return buffer.Bytes()
}
