package osquery

import (
	"github.com/vela-security/vela-public/lua"
)

func (o *osqueryEx) queryL(L *lua.LState) int {
	L.Push(o.query(L.IsString(1)))
	return 1
}

func (o *osqueryEx) startL(L *lua.LState) int {
	xEnv.Start(L, o).From(o.cfg.co.CodeVM()).Do()
	return 0
}

func (o *osqueryEx) defL(L *lua.LState) int {
	if osq == nil {
		osq = o
	}
	return 0
}

func (o *osqueryEx) Index(L *lua.LState, key string) lua.LValue {
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
