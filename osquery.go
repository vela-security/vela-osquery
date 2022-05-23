package osquery

import (
	"fmt"
	"github.com/osquery/osquery-go"
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/grep"
	"github.com/vela-security/vela-public/lua"
	"gopkg.in/tomb.v2"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"
)

var typeof = reflect.TypeOf((*osqueryEx)(nil)).String()

var osq *osqueryEx

type osqueryEx struct {
	lua.ProcEx
	cfg *config
	tom *tomb.Tomb
	cmd *exec.Cmd
	mux sync.Mutex
	cli *osquery.ExtensionManagerClient
}

func newOsq(cfg *config) *osqueryEx {
	o := &osqueryEx{cfg: cfg}
	o.V(lua.PTInit, typeof)
	return o
}

func (o *osqueryEx) Name() string {
	return o.cfg.name
}

func (o *osqueryEx) Type() string {
	return typeof
}

func (o *osqueryEx) Code() string {
	return o.cfg.co.CodeVM()
}

func (o *osqueryEx) Start() error {
	o.tom = new(tomb.Tomb)

	if e := o.forkExec(); e != nil {
		return e
	}
	return nil
}

func (o *osqueryEx) deletePidFile() {
	file := filepath.Join(o.cfg.prefix, "osquery.pid")
	if e := os.Remove(file); e != nil {
		xEnv.Errorf("delete %s error %v", file, e)
	} else {
		xEnv.Errorf("delete %s succeed", file)
	}
}

func (o *osqueryEx) deleteLogFile() {
	d, err := os.ReadDir(o.cfg.prefix)
	if err != nil {
		xEnv.Errorf("find %s  prefix dir fail", o.cfg.prefix)
		return
	}

	filter := grep.New("*.log")
	for _, item := range d {
		if item.IsDir() {
			continue
		}

		if !filter(item.Name()) {
			continue
		}

		file := filepath.Join(o.cfg.prefix, item.Name())
		if er := os.Remove(file); er != nil {
			xEnv.Errorf("delete %s error %v", file, er)
		} else {
			xEnv.Errorf("delete %s succeed", file)
		}
	}
}

func (o *osqueryEx) deleteLockFile() {
	lock := filepath.Join(o.cfg.prefix, "osquery.db", "LOCK")
	os.Remove(lock)

	current := filepath.Join(o.cfg.prefix, "osquery.db", "CURRENT")
	os.Remove(current)
}

func (o *osqueryEx) clean() {
	if runtime.GOOS != "windows" {
		return
	}

	o.deleteLockFile()
	o.deletePidFile()
	o.deleteLogFile()
}

func (o *osqueryEx) Close() error {
	defer o.clean()

	if o.cmd != nil && o.cmd.Process != nil {
		o.cmd.Process.Kill()
	}

	if osq != nil {
		osq = nil
	}

	if o.cli != nil {
		o.cli.Close()
	}

	o.tom.Kill(fmt.Errorf("osquery kill"))
	o.V(lua.PTClose, time.Now())

	return nil
}

func (o *osqueryEx) wait() {
	if er := o.cmd.Wait(); er != nil {
		audit.Errorf("osquery osq start fail %v", er).From(o.Code()).Log().Put()
	} else {
		audit.Debug("osquery osq start succeed").From(o.Code()).Log().Put()
	}
}

func (o *osqueryEx) Verbose(r io.Reader) {
	buf := make([]byte, 4096)

	for {
		select {
		case <-o.tom.Dying():
			audit.Debug("osquery debug verbose over.")

		default:
			n, err := r.Read(buf)
			switch err {
			case nil:
				if n == 0 {
					time.After(5 * time.Second)
					continue
				}
				audit.Debug("osquery verbose %s", auxlib.B2S(buf[:n]))

			case io.EOF:
				time.After(60 * time.Second)

			default:
				audit.Errorf("osquery verbose scanner fail %v", err).Log().From(o.CodeVM()).Put()
				return
			}
		}
	}

}

func (o *osqueryEx) forkExec() error {
	o.mux.Lock()
	defer o.mux.Unlock()

	path := filepath.Join("./", o.cfg.path)
	cmd := exec.Command(path, o.cfg.Args()...)
	cmd.SysProcAttr = newSysProcAttr()

	out, err := cmd.StderrPipe()
	if err != nil {
		audit.Errorf("osquery osq stdout pipe got fail %v", err).Log().From(o.CodeVM()).Put()
		return err
	}

	if e := cmd.Start(); e != nil {
		return e
	}

	o.cmd = cmd
	go o.Verbose(out)
	go o.wait()

	return nil
}

func (o *osqueryEx) detect(poll int) bool {
	return detect(o.cfg.sock, poll)
}

func (o *osqueryEx) query(sql string) reply {
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

func (o *osqueryEx) connect() error {
	if !o.detect(1) {
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
