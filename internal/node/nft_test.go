package node

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"mocat/internal/api"
	"mocat/internal/node/obfs"
)

func testRuleset() string {
	fh := &groupRT{key: "fh", plugin: &obfs.Fake{Type: api.ObfsFakeHTTP, Bin: "/bin/true"}, idx: 1, queue: queueBase + 1, mark: procMark(1), refs: 2}
	fs := &groupRT{key: "fs", plugin: &obfs.Fake{Type: api.ObfsFakeSIP, Bin: "/bin/true"}, idx: 2, queue: queueBase + 2, mark: procMark(2), refs: 1}
	rules := []nftRule{
		{rule: api.Rule{ID: "a", Protocol: "tcp", ListenPort: 8080, TargetHost: "1.2.3.4", TargetPort: 80, Backend: api.BackendNft, Obfs: api.Obfs{Type: api.ObfsFakeHTTP}}, ip: "1.2.3.4", mark: ruleMark(1), group: fh},
		{rule: api.Rule{ID: "b", Protocol: "tcp", ListenPort: 8081, TargetHost: "1.2.3.5", TargetPort: 80, Backend: api.BackendSocat, Obfs: api.Obfs{Type: api.ObfsFakeHTTP}}, ip: "1.2.3.5", mark: ruleMark(2), group: fh},
		{rule: api.Rule{ID: "c", Protocol: "udp", ListenPort: 5000, ListenAddr: "10.0.0.1", TargetHost: "1.2.3.6", TargetPort: 5060, Backend: api.BackendNft, Obfs: api.Obfs{Type: api.ObfsFakeSIP}}, ip: "1.2.3.6", mark: ruleMark(3), group: fs},
		{rule: api.Rule{ID: "d", Protocol: "udp", ListenPort: 5001, TargetHost: "1.2.3.7", TargetPort: 53, Backend: api.BackendSocat, Obfs: api.Obfs{Type: api.ObfsNone}}, ip: "1.2.3.7", mark: ruleMark(4)},
	}
	return buildRuleset(rules, []*groupRT{fh, fs}, map[string]counterVal{"r_a_up": {Packets: 3, Bytes: 300}}, false)
}

func TestBuildRuleset(t *testing.T) {
	s := testRuleset()
	must := []string{
		// 原子替换
		"table inet mocat {}\ndelete table inet mocat\n",
		// 计数器保留初值
		"counter r_a_up { packets 3 bytes 300 }",
		// nft 后端 DNAT + 标记
		"meta nfproto ipv4 meta l4proto tcp th dport 8080 ct mark set ct mark and 0x0000ffff or 0x6d010000 dnat ip to 1.2.3.4:80",
		"ip daddr 10.0.0.1",
		"ct status dnat ct mark and 0xffff0000 == 0x6d010000 masquerade",
		// socat 出站连接按 SO_MARK 打连接标记
		"meta skgid 1828716546 ct direction original ct mark set ct mark and 0x0000ffff or 0x6d020000",
		// 伪装进程重新注入的报文在入口链也要跳过
		"meta mark and 0xffff0000 == 0x6e010000 accept",
		// FakeHTTP：SYN-ACK 送队列，且不带 bypass（fail-closed）
		"ct mark and 0xffff0000 == 0x6d010000 ct direction reply tcp flags & (syn|ack) == syn|ack queue num 3101",
		"ct mark and 0xffff0000 == 0x6d020000 ct direction reply tcp flags & (syn|ack) == syn|ack queue num 3101",
		// nft 后端 + FakeHTTP 丢弃 TFO SYN
		"tcp option fastopen exists drop",
		// FakeSIP：每个流前 5 个出站报文送队列
		"ct mark and 0xffff0000 == 0x6d030000 ct direction original meta l4proto udp ct original packets <= 5 queue num 3102",
		// 伪装进程自发报文不进 conntrack
		"meta mark and 0xffff0000 == 0x6e010000 notrack",
		// 伪装引起的 ICMP 超时不转回客户端
		"ct mark and 0xffff0000 == 0x6d010000 ct state related icmp type time-exceeded drop",
		// FakeSIP 重发的原报文副本被丢弃（TTL 不等于伪装 TTL）
		"meta mark and 0xffff0000 == 0x6e020000 meta l4proto udp ip ttl != 3 drop",
		// 统计
		`ct mark and 0xffff0000 == 0x6d040000 ct direction original counter name "r_d_up"`,
		`ct mark and 0xffff0000 == 0x6d040000 ct direction reply counter name "r_d_down"`,
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("规则集缺少: %s\n---\n%s", m, s)
		}
	}
	if strings.Contains(s, "bypass") {
		t.Error("规则集中不得出现 bypass（N-27）")
	}
	// 未伪装规则不能进队列
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "0x6d040000") && strings.Contains(l, "queue") {
			t.Errorf("未伪装规则不应送队列: %s", l)
		}
	}
}

func TestBuildRulesetEmpty(t *testing.T) {
	s := buildRuleset(nil, nil, nil, false)
	if s != "table inet mocat {}\ndelete table inet mocat\n" {
		t.Fatalf("空规则集应只删表: %q", s)
	}
}

// 需要 root 和 nft：MOCAT_NFT_TEST=1 go test ./internal/node -run Kernel
func TestRulesetKernelCheck(t *testing.T) {
	if os.Getenv("MOCAT_NFT_TEST") != "1" {
		t.Skip("设置 MOCAT_NFT_TEST=1 并以 root 运行以检查内核能否接受规则集")
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(testRuleset())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -c 失败: %v\n%s", err, out)
	}
}

func TestFakeCommand(t *testing.T) {
	f := &obfs.Fake{Type: api.ObfsFakeHTTP, Bin: "/x/fakehttp"}
	args, err := f.Command(api.Obfs{Type: api.ObfsFakeHTTP, Params: json.RawMessage(`{"host":"a.com","ttl":4,"repeat":3}`)},
		obfs.GroupEnv{Queue: 3101, Mark: procMark(1), Mask: markMask, StateDir: t.TempDir(), Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, m := range []string{"-f", "-1", "-g", "-n 3101", "-t 4", "-r 3", "-h a.com", "-m 1845559296"} {
		if !strings.Contains(got, m) {
			t.Errorf("参数缺少 %q: %s", m, got)
		}
	}
	sip := &obfs.Fake{Type: api.ObfsFakeSIP, Bin: "/x/fakesip"}
	sargs, _ := sip.Command(api.Obfs{Type: api.ObfsFakeSIP}, obfs.GroupEnv{Queue: 3102, Mark: procMark(2), Mask: markMask, StateDir: t.TempDir()})
	if !strings.Contains(strings.Join(sargs, " "), "-f -0 -g -a") || !strings.Contains(strings.Join(sargs, " "), "-u sip:") {
		t.Errorf("fakesip 参数错误: %v", sargs)
	}
	// 参数相同则分组键相同，不同则不同（N-54）
	k1, _ := f.GroupKey(api.Obfs{Type: api.ObfsFakeHTTP, Params: json.RawMessage(`{"host":"a.com"}`)})
	k2, _ := f.GroupKey(api.Obfs{Type: api.ObfsFakeHTTP, Params: json.RawMessage(`{"host":"a.com","ttl":3}`)})
	k3, _ := f.GroupKey(api.Obfs{Type: api.ObfsFakeHTTP, Params: json.RawMessage(`{"host":"b.com"}`)})
	if k1 != k2 || k1 == k3 {
		t.Errorf("分组键错误: %s %s %s", k1, k2, k3)
	}
}

func TestSocatArgs(t *testing.T) {
	a := socatArgs(api.Rule{Protocol: "tcp", ListenPort: 1000, TargetPort: 80}, "1.2.3.4")
	if strings.Join(a, " ") != "TCP4-LISTEN:1000,reuseaddr,fork TCP4:1.2.3.4:80" {
		t.Errorf("tcp: %v", a)
	}
	a = socatArgs(api.Rule{Protocol: "udp", ListenPort: 1000, ListenAddr: "10.0.0.1", TargetPort: 53}, "2001:db8::1")
	if strings.Join(a, " ") != "-T 120 UDP4-LISTEN:1000,reuseaddr,fork,bind=10.0.0.1 UDP6:[2001:db8::1]:53" {
		t.Errorf("udp6: %v", a)
	}
}
