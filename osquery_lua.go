package osquery

import (
	"github.com/vela-security/vela-public/lua"
)

func (o *osq) queryL(L *lua.LState) int {
	L.Push(o.query(L.IsString(1)))
	return 1
}

func (o *osq) startL(L *lua.LState) int {
	xEnv.Start(L, o).From(o.cfg.co.CodeVM()).Do()
	return 0
}

func (o *osq) defL(L *lua.LState) int {
	if client == nil {
		client = o
	}
	return 0
}

func (o *osq) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "query":
		return L.NewFunction(o.queryL)

	case "start":
		return L.NewFunction(o.startL)

	case "default":
		return L.NewFunction(o.defL)
	}
	return lua.LNil
}
