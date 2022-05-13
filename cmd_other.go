//go:build !windows && !plan9
// +build !windows,!plan9

package osquery

import (
	"syscall"
)

func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		//Setsid: true,
		Setpgid: true,
	}
}
