package osquery

import (
	"fmt"
	"github.com/osquery/osquery-go"
	"github.com/vela-security/vela-public/lua"
	"gopkg.in/tomb.v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"time"
)

var typeof = reflect.TypeOf((*osq)(nil)).String()

var client *osq

type osq struct {
	lua.ProcEx
	cfg *config
	tom *tomb.Tomb
	cmd *exec.Cmd
	mux sync.Mutex
	cli *osquery.ExtensionManagerClient
}

func newOsq(cfg *config) *osq {
	o := &osq{cfg: cfg}
	o.V(lua.PTInit, typeof)
	return o
}

func (o *osq) Name() string {
	return o.cfg.name
}

func (o *osq) Type() string {
	return typeof
}

func (o *osq) Code() string {
	return o.cfg.co.CodeVM()
}

func (o *osq) Start() error {
	o.tom = new(tomb.Tomb)

	if e := o.forkExec(); e != nil {
		return e
	}
	return nil
}

func (o *osq) Close() error {
	if o.cmd != nil && o.cmd.Process != nil {
		o.cmd.Process.Kill()
	}

	if client != nil {
		client = nil
	}

	if o.cli != nil {
		o.cli.Close()
	}

	o.tom.Kill(fmt.Errorf("osquery kill"))
	o.V(lua.PTClose, time.Now())
	return nil
}

func (o *osq) forkExec() error {
	o.mux.Lock()
	defer o.mux.Unlock()
	path := filepath.Join("./", o.cfg.path)

	cmd := exec.Command(path, o.cfg.Args()...)
	cmd.SysProcAttr = newSysProcAttr()

	if e := cmd.Start(); e != nil {
		return e
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	o.cmd = cmd
	o.tom.Go(cmd.Wait)
	return nil
}

func (o *osq) detect(poll int) bool {
	if _, err := os.Stat(o.cfg.sock); err == nil {
		return true
	}

	if poll == 0 {
		return false
	}

	tk := time.NewTicker(time.Second)
	defer tk.Stop()

	i := 0
	for {
		select {
		case <-tk.C:
			i++
			if _, err := os.Stat(o.cfg.sock); err == nil {
				return true
			}

			if i >= poll {
				return false
			}

		case <-o.tom.Dying():
			return false

		}
	}

	return false
}

func (o *osq) query(sql string) reply {
	if o.cli != nil {
		goto query
	}

	if err := o.connect(); err != nil {
		return newReply(nil, err)
	}

query:
	v, e := o.cli.Query(sql)
	return newReply(v, e)
}

func (o *osq) connect() error {
	if !o.detect(0) {
		return fmt.Errorf("%s not found %s", o.Name(), o.cfg.sock)
	}

	timeout := time.Duration(o.cfg.timeout) * time.Second
	cli, err := osquery.NewClient(o.cfg.sock, timeout)
	if err != nil {
		return err
	}
	o.cli = cli
	return nil
}
