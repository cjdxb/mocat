# mocat

链式端口转发 + FakeHTTP / FakeSIP 伪装的管理工具，包括：

- **mocat-node**：节点程序。用 socat 或 nftables DNAT 转发，作为子进程托管 fakehttp / fakesip，在本节点的出站方向注入伪装报文。
- **mocat-controller**：控制端，提供中文 Web 界面，负责节点管理、规则和转发链编排、状态与流量监控。

需求见 [docs/需求文档-v1.md](docs/需求文档-v1.md)。只支持 Linux，架构为 amd64 / arm64。

## 目录

```
cmd/mocat-node, cmd/mocat-controller   程序入口
internal/api          控制通道数据结构与校验（两端共用）
internal/node         节点：环境检查、子进程托管、nft 规则生成、规则编排、管理 API
internal/node/obfs    伪装插件接口与 FakeHTTP/FakeSIP 插件
internal/controller   控制端：SQLite 存储、链编译、同步器、REST API、Web（web/ 打包进二进制）
deploy/               systemd 服务文件
scripts/              打包、fakehttp/fakesip 静态编译、端到端测试
```

## 构建

```bash
make build                 # bin/mocat-node, bin/mocat-controller
make test                  # 单元测试
BUILD_FAKE=1 make package  # 用 docker 静态编译 fakehttp/fakesip，然后生成 dist/*.tar.gz
sudo scripts/e2e.sh bin/mocat-controller bin/mocat-node        # 转发/鉴权/缓存/清理端到端测试（root、nft、python3、curl）
sudo scripts/e2e-obfs.sh bin/mocat-controller bin/mocat-node   # 伪装抓包测试（另需 socat、tcpdump，fakehttp/fakesip 与 mocat-node 同目录）
```

## 部署

**控制端**

```bash
tar xzf mocat-controller-linux-amd64.tar.gz -C /opt && mv /opt/mocat-controller-linux-amd64 /opt/mocat-controller
cp /opt/mocat-controller/mocat-controller.service /etc/systemd/system/
systemctl enable --now mocat-controller
journalctl -u mocat-controller | grep password   # 首次启动时打印 admin 初始密码
```

可选配置 `/etc/mocat/controller.json`：

```json
{"listen":"0.0.0.0:8443","data_dir":"/var/lib/mocat-controller","public_url":"https://控制端IP:8443",
 "tls_cert":"/path/cert.pem","tls_key":"/path/key.pem"}
```

不配置证书时自动生成自签名证书。忘记密码时运行 `mocat-controller reset-password`。

**节点**：把 `mocat-node-linux-*.tar.gz` 放到控制端的 `/var/lib/mocat-controller/packages/` 下，然后在 Web 上新建节点，复制页面给出的一键安装命令到节点上执行。这条命令会固定控制端证书公钥（`--pinnedpubkey`）。也可以手动解压到 `/opt/mocat`，再执行页面上的「手动」命令。

节点依赖 `nft`、`socat`，`conntrack` 可选。运行 `mocat-node check` 查看环境检查结果。节点的管理端口（默认 9443）必须能被控制端访问。

## 关键设计

- **控制通道**：控制端通过 HTTPS 主动连接节点，每个请求带 Bearer Token。节点首次启动时生成自签名证书，控制端第一次连接时记录证书指纹，之后指纹变化就拒绝连接并告警。配置带版本号，节点只接受比当前更新的版本，并缓存到 `state_dir/config.json`，重启后不依赖控制端也能恢复。
- **nftables**：所有规则都放在独立的 `inet mocat` 表里，每次在一个 nft 事务中原子替换，计数器带初值，所以累计流量不会清零。连接标记只用 mark 的高 16 位：规则用 `0x6dXX0000`，伪装进程自己发的报文用 `0x6eXX0000`。
  - socat 后端：每条规则的 socat 以独立 GID（`0x6d000000 + 槽位`）运行，nft 按 `meta skgid` 识别它主动发起的连接，从第一个 SYN 起就打上连接标记。socat 的 `setsockopt` SO_MARK 要到 connect 之后才生效，不能用。
  - nft 后端：DNAT 时同时设置 ct mark，再 masquerade。
  - 两种后端都按 ct mark 统计上下行流量和连接数。
- **伪装（先伪装，后发数据）**：
  - FakeHTTP：目标返回的 SYN-ACK 送入 NFQUEUE，fakehttp 先发出伪造的 HTTP 请求，再放行 SYN-ACK。nft 后端会丢弃带 TFO 的 SYN。
  - FakeSIP：每个 UDP 流的前 5 个出站报文送入队列（依赖 `nf_conntrack_acct=1`，节点会自动开启）。
  - 队列规则**不加 bypass**，伪装进程不在时报文直接被内核丢弃（fail-closed）。
  - 启用顺序：伪装进程启动，确认其 NFQUEUE 已绑定，然后安装 nft 规则，最后开启转发。停止时顺序相反。
  - fakehttp/fakesip 的启动参数为 `-f <-1|-0> -g -a -n Q -m MARK -x MASK -t TTL -r N -h HOST|-u URI|-b FILE`。FakeHTTP 用 `-1`；FakeSIP 的"本机发出报文前注入"分支在上游由 `-0` 控制，所以用 `-0`。参数相同的规则共用一个进程。
  - 伪装进程放行原报文时会带自己的 fwmark 重新注入，入口链和出口链都会跳过这类报文，避免再次进入队列。
  - FakeSIP 注入后还会用原始套接字把原报文再发一遍。mocat 在 raw output 链中丢弃"带该进程 fwmark、且 TTL 不等于伪装 TTL"的副本，避免业务报文重复。
  - 伪装报文在中途过期时，路由器返回的 ICMP Time Exceeded 属于该连接的 RELATED 报文，会被转回客户端，让握手中的连接中止（nft 后端稳定复现）。mocat 会丢弃这类 ICMP。
- **转发链**：节点只理解单条规则。控制端把链展开成每个节点的规则：第 i 跳的目标是第 i+1 跳的数据面地址加入口端口。端口填 0 时从 20000-29999 中自动分配。

## PoC 验证结果（附录 A.5）

`scripts/e2e-obfs.sh` 在 client → 节点 → 路由器 → 目标 拓扑下，用伪装 TTL=1 加节点出口抓包，验证了以下各项（fakehttp 0.9.18 / fakesip 0.9.1，未修改上游代码）：

| 项 | 结论 |
| --- | --- |
| 1 多实例 | 用 `-f` 加不同的队列号和 fwmark，多个实例可同时运行；参数相同的规则共用进程 |
| 2 socat 后端 | 可以触发伪装，但须按 skgid 打标记（见上） |
| 3 nft DNAT 后端 | 可以触发伪装，伪装报文的源地址和序列号正确；须丢弃 RELATED 的 ICMP 超时 |
| 4 FakeSIP 重复原报文 | 会重复发送原报文，已在 nft 中按 TTL 丢弃副本 |
| 6 先伪装后数据 | TCP/UDP × socat/nft 四种组合，每条流的第一个有载荷报文都是伪装报文 |
| 7 失败即阻断 | 杀掉伪装进程期间，没有未伪装的业务报文发出；进程自动重启后转发恢复 |

5（amd64/arm64 静态编译）：本机只做了 amd64 动态编译，`scripts/build-fake.sh` 还没有实际运行过。

## 已知限制

- 上游的 `FAIL_OPEN`（队列满时直接放行）没有修改。本项目连接数少，触发概率低。
- 跳数估算（`-y`，N-36）没有开放，固定用 `-g`，以满足 N-29。
- 内核不支持 `fib` 时（例如 WSL），nft 后端的 DNAT 不限定目的地址必须是本机。
- 主机 forward 链的默认策略如果是 drop，需要自行放行 mocat 的转发流量。
- 证书指纹是首次连接时信任（TOFU）；mTLS（A-08）属于 P2。
