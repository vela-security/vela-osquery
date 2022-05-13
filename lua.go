package osquery

import (
	"fmt"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var (
	xEnv assert.Environment
)

/*
	local cli = rock.osquery{
		name  = "client",
		path  = "share/software/osqueryd",
		flags = {"a=123" , "bb=456" , "xx==789"}
	}
	cli.start()

	local rx = cli.query("select * from aa")
*/

func constructor(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, typeof)
	if proc.IsNil() {
		proc.Set(newOsq(cfg))
	} else {
		o := proc.Data.(*osq)
		xEnv.Free(o.cfg.co)
		o.cfg = cfg
	}

	L.Push(proc)
	return 1
}

func queryL(L *lua.LState) int {
	if client == nil {
		L.Push(newReply(nil, fmt.Errorf("not found osquery client")))
		return 1
	}

	return client.queryL(L)
}

func WithEnv(env assert.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	kv.Set("client", lua.NewFunction(constructor))
	kv.Set("query", lua.NewFunction(queryL))
	env.Set("osquery", kv)
}
