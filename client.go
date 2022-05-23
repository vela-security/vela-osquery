package osquery

import (
	"fmt"
	"github.com/osquery/osquery-go"
	"github.com/vela-security/vela-public/lua"
	"reflect"
	"time"
)

var (
	clientTypeof = reflect.TypeOf((*Client)(nil)).String()
)

type Client struct {
	lua.ProcEx

	sock   string
	inline *osquery.ExtensionManagerClient
}

func newClient(sock string) *Client {
	return &Client{sock: sock}
}

func (c *Client) Name() string {
	return "osquery.client"
}

func (c *Client) Type() string {
	return clientTypeof
}

func (c *Client) Start() error {
	cli, err := connect(c.sock, 5) //5s
	if err != nil {
		return err
	}
	c.inline = cli
	c.V(lua.PTRun, time.Now())
	return nil
}

func (c *Client) Close() error {
	if c.inline == nil {
		return nil
	}

	c.inline.Close()
	return nil
}

func (c *Client) queryL(L *lua.LState) int {
	var r reply
	if c.inline == nil {
		r = newReply(nil, fmt.Errorf("osquery connect %s fail", c.sock))
	} else {
		sql := L.CheckString(1)
		v, err := c.inline.Query(sql)
		r = newReply(v, err)
	}
	L.Push(r)
	return 1
}

func (c *Client) Index(L *lua.LState, key string) lua.LValue {
	if key == "query" {
		return lua.NewFunction(c.queryL)
	}

	return lua.LNil
}
