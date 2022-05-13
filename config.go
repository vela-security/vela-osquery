package osquery

import (
	"fmt"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"path/filepath"
	"runtime"
	"strings"
)

type config struct {
	name    string
	path    string
	hash    string
	sock    string
	flags   []string
	timeout int
	co      *lua.LState
}

func newConfig(L *lua.LState) *config {
	cfg := &config{name: "osquery", timeout: 5}

	if L.CodeVM() != "vela-osquery" {
		L.RaiseError("not allow %v create osquery client", L.CodeVM())
		return cfg
	}

	tab := L.CheckTable(1)

	tab.Range(func(key string, val lua.LValue) {
		cfg.NewIndex(L, key, val)
	})

	cfg.co = xEnv.Clone(L)

	if err := cfg.valid(); err != nil {
		L.RaiseError("%v", err)
		return nil
	}
	return cfg

}

func (cfg *config) Args() []string {
	var flags []string

	shell := false
	for _, item := range cfg.flags {
		if strings.HasPrefix(item, "extensions_socket=") {
			shell = true
		}
		flags = append(flags, "--"+item)
	}

	if !shell {
		if runtime.GOOS == "windows" {
			flags = append(flags, "--extensions_socket=\""+cfg.sock+"\"")
		} else {
			flags = append(flags, "--extensions_socket="+cfg.sock)
		}
	}
	return flags
}

func (cfg *config) NewIndex(L *lua.LState, key string, val lua.LValue) bool {
	switch key {
	case "name":
		cfg.name = val.String()

	case "path":
		cfg.path = filepath.Clean(val.String())

	case "sock":
		cfg.sock = val.String()

	case "hash":
		cfg.hash = val.String()

	case "timeout":
		n := lua.IsInt(val)
		if n > 0 {
			cfg.timeout = lua.IsInt(val)
		}

	case "flags":

		switch val.Type() {

		case lua.LTString:
			cfg.flags = []string{val.String()}

		case lua.LTTable:
			cfg.flags = auxlib.LTab2SS(val.(*lua.LTable))

		default:
			L.RaiseError("invalid flags")
		}

	default:
		return false

	}

	return true
}

func (cfg *config) valid() error {
	if e := auxlib.Name(cfg.name); e != nil {
		return e
	}

	if len(cfg.flags) == 0 {
		return fmt.Errorf("not found flags")
	}

	hash, err := auxlib.FileMd5(cfg.path)
	if err != nil {
		return err
	}

	path, err := filepath.Abs(cfg.path)
	if err != nil {
		return fmt.Errorf("abs path %v", err)
	}
	cfg.path = path

	if hash != cfg.hash {
		return fmt.Errorf("checksum fail got %v", hash)
	}

	return nil
}
