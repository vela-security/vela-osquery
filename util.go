package osquery

import (
	"fmt"
	"github.com/osquery/osquery-go"
	"os"
	"time"
)

func detect(sock string, poll int) bool {
	if _, err := os.Stat(sock); err == nil {
		return true
	}

	if poll == 0 {
		return false
	}

	if poll > 9 {
		poll = 9
	}

	tk := time.NewTicker(time.Second)
	defer tk.Stop()

	i := 0
	for range tk.C {
		i++
		if _, err := os.Stat(sock); err == nil {
			return true
		}

		if i >= poll {
			return false
		}
	}

	return false

}

func connect(sock string, timeout int) (*osquery.ExtensionManagerClient, error) {
	if !detect(sock, 1) {
		return nil, fmt.Errorf("osquery pipe %s not found", sock)
	}

	deadline := time.Duration(timeout) * time.Second
	cli, err := osquery.NewClient(sock, deadline)
	if err != nil {
		return nil, err
	}
	return cli, nil
}
