# osquery

```text
    作者: vela 
```

- [github.com/vela-security/vela-osuqery](https://github.com/vela-security/vela-osquery)

## vela.osquery.client
- [vela.osquery.client{name , path , hash , flags , socket , timeout} userdata](#)
- name: 进程名称
- path: osquery 可执行文件路径
- hash: osquery 的checksum
- flags: osquery 配置参数 数组
- socket: socket api 路径
- timeout: 操作超时时间

#### 内部方法
- [userdata.query(sql) reply](结果)

```lua
    --windows
    local client

    if vela.windows then
        client = vela.osquery.client{
            name = "client",
            path = "share\\software\\osqueryd.exe",
            hash = "940df5da06c7738f2cf0b8aa2e198d3b",
            sock = "\\\\.\\pipe\\shell.em",
            flags = {
                [[allow_unsafe]],
                [[disable_extensions=false]],
                [[config_path=.osuqery.conf]],
                [[logger_path=share]],
                [[database_path="share\osquery.db"]],
            }
        }
    else
        client = vela.osquery.client{
            name = "client",
            path = [[share/software/osqueryd.x]],
            hash = [[940df5da06c7738f2cf0b8aa2e198d3b]],
            sock = [[shell/shell.em]],
            flags = {
                [[disable_extensions=false]],
                [[extensions_socket="share/shell.em"]],
                [[database_path="share/osquery.db"]],
            }
        }

    end


    -- 启动
    client.start()
    -- 设置默认
    client.default()

    -- 私有
    inline(client)

    local r = client.query("select * from last") --linux
```

## vela.query
- [vela.osquery.query(sql) reply](#内部接口)
- 注意: 需要先client.default()设置默认client 才能全局调用

## 内部接口
- 类型: userdata
- [reply.ok](#)
- [reply.msg](#)
- [reply.raw](#)
- [reply.code](#)
- [reply.uuid](#)
- [reply.warp](#) &nbsp;错误信息
- [reply.ipairs(function)](#) &nbsp; 轮询回调
```lua
    local rx = vela.osquery.query("select * from last")
    print(rx.ok)
    print(rx.msg)
    print(rx.raw)
    print(rx.code)
    print(rx.uuid)
    print(rx.warp)
    
    rx.ipairs(function(row)
        print(row.username)
        print(row.tty)
        print(row.pid)
        print(row.type)
        print(row.type_name)
        print(row.time)
        print(row.host)
    end)
```