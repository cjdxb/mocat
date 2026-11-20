package obfs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"mocat/internal/api"
)

// Fake 复用 FakeHTTP / FakeSIP 程序的插件（N-51）。
//
// 进程参数：-f 跳过其自带防火墙规则；-g 关闭跳数估算，
// 避免“判定对端为本地而跳过注入”（N-29）；-a 不按网卡过滤（匹配由 mocat 的 nft 规则完成）。
// 方向：FakeHTTP 用 -1（收到对端 SYN-ACK 时注入）；FakeSIP 在“本机发出的 UDP 报文”分支注入，
// 该分支在上游代码中由 -0 控制（见 FakeSIP src/rawsend.c），所以 FakeSIP 用 -0。
type Fake struct {
	Type string // api.ObfsFakeHTTP / api.ObfsFakeSIP
	Bin  string
}

func (f *Fake) Name() string { return f.Type }

func (f *Fake) Protocol() string {
	if f.Type == api.ObfsFakeHTTP {
		return api.ProtoTCP
	}
	return api.ProtoUDP
}

func (f *Fake) Binary() string { return f.Bin }

func (f *Fake) params(o api.Obfs) (api.FakeParams, error) {
	if err := api.ValidateObfs(f.Protocol(), o); err != nil {
		return api.FakeParams{}, err
	}
	return api.ParseFakeParams(o)
}

func (f *Fake) GroupKey(o api.Obfs) (string, error) {
	p, err := f.params(o)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(append([]byte(f.Type+"|"), b...))
	return f.Type + ":" + hex.EncodeToString(sum[:8]), nil
}

func (f *Fake) Command(o api.Obfs, g GroupEnv) ([]string, error) {
	p, err := f.params(o)
	if err != nil {
		return nil, err
	}
	dir := "-1"
	if f.Type == api.ObfsFakeSIP {
		dir = "-0"
	}
	args := []string{
		"-f", dir, "-g", "-a",
		"-n", strconv.Itoa(g.Queue),
		"-m", strconv.FormatUint(uint64(g.Mark), 10),
		"-x", strconv.FormatUint(uint64(g.Mask), 10),
		"-t", strconv.Itoa(p.TTL),
		"-r", strconv.Itoa(p.Repeat),
	}
	if p.PayloadB64 != "" {
		data, err := base64.StdEncoding.DecodeString(p.PayloadB64)
		if err != nil {
			return nil, err
		}
		fn := filepath.Join(g.StateDir, fmt.Sprintf("payload-%s-%d.bin", f.Type, g.Index))
		if err := os.WriteFile(fn, data, 0o600); err != nil {
			return nil, err
		}
		args = append(args, "-b", fn)
	} else if f.Type == api.ObfsFakeHTTP {
		args = append(args, "-h", p.Host)
	} else {
		args = append(args, "-u", p.URI)
	}
	return args, nil
}

// GroupRules：FakeSIP 发出伪装报文后，会用原始套接字把原报文再发一遍，同时又放行队列中的原报文，
// 导致业务报文重复。重发的副本带伪装进程的 fwmark、TTL 为原值；伪装报文的 TTL 是配置值，
// 因此丢弃“带该 fwmark 且 TTL 不等于配置值”的报文即可去掉副本。
func (f *Fake) GroupRules(o api.Obfs, g GroupEnv) Rules {
	if f.Type != api.ObfsFakeSIP {
		return Rules{}
	}
	p, err := f.params(o)
	if err != nil {
		return Rules{}
	}
	m := fmt.Sprintf("meta mark and 0x%08x == 0x%08x", g.Mask, g.Mark)
	return Rules{Raw: []string{
		fmt.Sprintf("%s meta l4proto udp ip ttl != %d drop", m, p.TTL),
		fmt.Sprintf("%s meta l4proto udp ip6 hoplimit != %d drop", m, p.TTL),
	}}
}

func (f *Fake) Rules(r RuleEnv, g GroupEnv) Rules {
	match := fmt.Sprintf("ct mark and 0x%08x == 0x%08x", r.Mask, r.CtMark)
	var out Rules
	// 伪装报文在中途过期时，沿途路由器返回的 ICMP 超时会作为 RELATED 报文被转回客户端，
	// 可能让尚在握手中的连接被中止；这些 ICMP 是伪装本身造成的，直接丢弃。
	out.Pre = append(out.Pre,
		fmt.Sprintf("%s ct state related icmp type time-exceeded drop", match),
		fmt.Sprintf("%s ct state related icmpv6 type time-exceeded drop", match))
	switch f.Type {
	case api.ObfsFakeHTTP:
		// nft 后端下客户端 SYN 可能携带 TFO 数据，会在伪装报文之前到达目标，直接丢弃（N-25），
		// 客户端会退回普通握手重试。
		if r.Backend == api.BackendNft {
			m := fmt.Sprintf("meta nfproto ipv4 tcp dport %d", r.ListenPort)
			if r.ListenAddr != "" && r.ListenAddr != "0.0.0.0" {
				m += " ip daddr " + r.ListenAddr
			}
			if r.HasFib {
				m += " fib daddr type local"
			}
			out.Pre = append(out.Pre, m+" tcp flags & (syn|ack) == syn tcp option fastopen exists drop")
		}
		// 截住目标返回的 SYN-ACK：伪装进程先发伪造 HTTP 请求，再放行 SYN-ACK。
		// 不加 bypass：进程不在时内核丢弃报文，连接无法建立（fail-closed，N-27）。
		out.Pre = append(out.Pre, fmt.Sprintf("%s ct direction reply tcp flags & (syn|ack) == syn|ack queue num %d", match, g.Queue))
	case api.ObfsFakeSIP:
		// 截住每个 UDP 流的前 5 个出站报文：先发伪造 SIP 报文，再放行原报文（N-26）。
		out.Post = append(out.Post, fmt.Sprintf("%s ct direction original meta l4proto udp ct original packets <= 5 queue num %d", match, g.Queue))
	}
	return out
}
