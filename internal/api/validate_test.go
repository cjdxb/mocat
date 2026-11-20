package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func base() Rule {
	return Rule{ID: "r1", Enabled: true, Protocol: ProtoTCP, ListenPort: 1000, TargetHost: "example.com", TargetPort: 80, Backend: BackendSocat, Obfs: Obfs{Type: ObfsNone}}
}

func TestValidateRule(t *testing.T) {
	cases := []struct {
		name string
		mod  func(r *Rule)
		err  string
	}{
		{"ok", func(r *Rule) {}, ""},
		{"ok fakehttp", func(r *Rule) { r.Obfs = Obfs{Type: ObfsFakeHTTP} }, ""},
		{"tcp 不能用 FakeSIP", func(r *Rule) { r.Obfs = Obfs{Type: ObfsFakeSIP} }, "FakeSIP 只能用于 UDP"},
		{"udp 不能用 FakeHTTP", func(r *Rule) { r.Protocol = ProtoUDP; r.Obfs = Obfs{Type: ObfsFakeHTTP} }, "FakeHTTP 只能用于 TCP"},
		{"端口越界", func(r *Rule) { r.ListenPort = 70000 }, "监听端口"},
		{"目标格式", func(r *Rule) { r.TargetHost = "bad host!" }, "目标地址"},
		{"nft 支持 IPv6", func(r *Rule) { r.Backend = BackendNft; r.TargetHost = "2001:db8::1" }, ""},
		{"nft v6→v6", func(r *Rule) { r.Backend = BackendNft; r.ListenAddr = "::"; r.TargetHost = "2001:db8::1" }, ""},
		{"nft 不能 v4→v6", func(r *Rule) { r.Backend = BackendNft; r.ListenAddr = "0.0.0.0"; r.TargetHost = "2001:db8::1" }, "不能在 IPv4 与 IPv6 之间转换"},
		{"nft 不能 v6→v4", func(r *Rule) { r.Backend = BackendNft; r.ListenAddr = "2001:db8::2"; r.TargetHost = "1.2.3.4" }, "不能在 IPv4 与 IPv6 之间转换"},
		{"nft 监听 v6 目标域名", func(r *Rule) { r.Backend = BackendNft; r.ListenAddr = "::" }, ""},
		{"socat 支持 IPv6", func(r *Rule) { r.TargetHost = "2001:db8::1" }, ""},
		{"socat v6→v4", func(r *Rule) { r.ListenAddr = "2001:db8::2"; r.TargetHost = "1.2.3.4" }, ""},
		{"监听地址格式", func(r *Rule) { r.ListenAddr = "abc" }, "监听地址"},
		{"TTL 越界", func(r *Rule) {
			r.Obfs = Obfs{Type: ObfsFakeHTTP, Params: json.RawMessage(`{"ttl":300}`)}
		}, "TTL"},
		{"SIP URI", func(r *Rule) {
			r.Protocol = ProtoUDP
			r.Obfs = Obfs{Type: ObfsFakeSIP, Params: json.RawMessage(`{"uri":"http://x"}`)}
		}, "SIP URI"},
		{"payload 非 base64", func(r *Rule) {
			r.Obfs = Obfs{Type: ObfsFakeHTTP, Params: json.RawMessage(`{"payload_b64":"%%%"}`)}
		}, "base64"},
	}
	for _, c := range cases {
		r := base()
		c.mod(&r)
		err := ValidateRule(&r)
		if c.err == "" && err != nil {
			t.Errorf("%s: 期望通过，得到 %v", c.name, err)
		}
		if c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: 期望包含 %q，得到 %v", c.name, c.err, err)
		}
	}
}

func TestValidateRulesConflicts(t *testing.T) {
	a, b := base(), base()
	b.ID = "r2"
	if err := ValidateRules([]Rule{a, b}, 9443); err == nil || !strings.Contains(err.Error(), "冲突") {
		t.Fatalf("期望端口冲突，得到 %v", err)
	}
	b.Protocol = ProtoUDP // 不同协议同端口不冲突
	if err := ValidateRules([]Rule{a, b}, 9443); err != nil {
		t.Fatal(err)
	}
	a.ListenPort = 9443
	if err := ValidateRules([]Rule{a}, 9443); err == nil || !strings.Contains(err.Error(), "管理端口") {
		t.Fatalf("期望与管理端口冲突，得到 %v", err)
	}
}

func TestParseFakeParamsDefaults(t *testing.T) {
	p, err := ParseFakeParams(Obfs{Type: ObfsFakeHTTP, Params: json.RawMessage(`{"ttl":5}`)})
	if err != nil {
		t.Fatal(err)
	}
	if p.TTL != 5 || p.Host == "" || p.Repeat != 2 {
		t.Fatalf("默认值未补全: %+v", p)
	}
}
