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
		name  = "osq",
		path  = "share/software/osqueryd",
		flags = {"a=123" , "bb=456" , "xx==789"}
	}
	cli.start()

	local rx = cli.query("select * from aa")
*/

func daemonL(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, typeof)
	if proc.IsNil() {
		proc.Set(newOsq(cfg))
	} else {
		o := proc.Data.(*osqueryEx)
		xEnv.Free(o.cfg.co)
		o.cfg = cfg
	}

	L.Push(proc)
	return 1
}

func queryL(L *lua.LState) int {
	if osq == nil {
		L.Push(newReply(nil, fmt.Errorf("not found osquery osq")))
		return 1
	}

	return osq.queryL(L)
}

func clientL(L *lua.LState) int {
	sock := L.CheckString(1)
	c := newClient(sock)
	proc := L.NewProc("osquery.client", clientTypeof)
	if proc.IsNil() {
		proc.Set(c)
	} else {
		old := proc.Data.(*Client)
		old.Close()
		proc.Set(c)
	}

	xEnv.Start(L, c).From(L.CodeVM()).Do()
	L.Push(proc)
	return 1
}

func WithEnv(env assert.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	kv.Set("daemon", lua.NewFunction(daemonL))
	kv.Set("query", lua.NewFunction(queryL))
	kv.Set("client", lua.NewFunction(clientL))
	env.Set("osquery", kv)
}
