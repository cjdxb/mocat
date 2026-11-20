package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

// IsValidHost 判断目标是否为合法的 IPv4 / IPv6 / 域名。
func IsValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	return hostnameRe.MatchString(h)
}

// IsIPv6 判断是否为 IPv6 字面量。
func IsIPv6(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.To4() == nil
}

// DefaultFakeParams 内置默认参数（C-31）。
func DefaultFakeParams(typ string) FakeParams {
	p := FakeParams{TTL: 3, Repeat: 2}
	switch typ {
	case ObfsFakeHTTP:
		p.Host = "www.speedtest.net"
	case ObfsFakeSIP:
		p.URI = "sip:10086@sip.example.com"
	}
	return p
}

// ParseFakeParams 解析并补全默认值。
func ParseFakeParams(o Obfs) (FakeParams, error) {
	p := DefaultFakeParams(o.Type)
	if len(o.Params) > 0 && string(o.Params) != "null" {
		var in FakeParams
		if err := json.Unmarshal(o.Params, &in); err != nil {
			return p, fmt.Errorf("伪装参数格式错误: %v", err)
		}
		if in.Host != "" {
			p.Host = in.Host
		}
		if in.URI != "" {
			p.URI = in.URI
		}
		if in.TTL != 0 {
			p.TTL = in.TTL
		}
		if in.Repeat != 0 {
			p.Repeat = in.Repeat
		}
		p.PayloadB64 = in.PayloadB64
	}
	return p, nil
}

// ValidateObfs 校验伪装配置与协议是否匹配以及参数合法性。
func ValidateObfs(proto string, o Obfs) error {
	switch o.Type {
	case "", ObfsNone:
		return nil
	case ObfsFakeHTTP:
		if proto != ProtoTCP {
			return fmt.Errorf("FakeHTTP 只能用于 TCP")
		}
	case ObfsFakeSIP:
		if proto != ProtoUDP {
			return fmt.Errorf("FakeSIP 只能用于 UDP")
		}
	default:
		return fmt.Errorf("未知伪装类型 %q", o.Type)
	}
	p, err := ParseFakeParams(o)
	if err != nil {
		return err
	}
	if p.TTL < 1 || p.TTL > 255 {
		return fmt.Errorf("TTL 必须在 1-255 之间")
	}
	if p.Repeat < 1 || p.Repeat > 10 {
		return fmt.Errorf("重复次数必须在 1-10 之间")
	}
	if o.Type == ObfsFakeHTTP && (p.Host == "" || strings.ContainsAny(p.Host, " \t\r\n/") || len(p.Host) > 253) {
		return fmt.Errorf("HTTP Host 不合法")
	}
	if o.Type == ObfsFakeSIP && (!strings.HasPrefix(strings.ToLower(p.URI), "sip:") || strings.ContainsAny(p.URI, " \t\r\n") || len(p.URI) > 255) {
		return fmt.Errorf("SIP URI 必须以 sip: 开头且不含空白")
	}
	if p.PayloadB64 != "" {
		b, err := base64.StdEncoding.DecodeString(p.PayloadB64)
		if err != nil {
			return fmt.Errorf("自定义载荷不是合法的 base64")
		}
		if len(b) == 0 || len(b) > 1400 {
			return fmt.Errorf("自定义载荷长度必须在 1-1400 字节之间")
		}
	}
	return nil
}

// ValidateRule 校验单条规则（不含跨规则冲突检查）。
func ValidateRule(r *Rule) error {
	if r.ID == "" {
		return fmt.Errorf("规则 ID 为空")
	}
	if r.Protocol != ProtoTCP && r.Protocol != ProtoUDP {
		return fmt.Errorf("协议必须是 tcp 或 udp")
	}
	if r.ListenPort < 1 || r.ListenPort > 65535 {
		return fmt.Errorf("监听端口必须在 1-65535 之间")
	}
	if r.TargetPort < 1 || r.TargetPort > 65535 {
		return fmt.Errorf("目标端口必须在 1-65535 之间")
	}
	if r.ListenAddr != "" {
		ip := net.ParseIP(r.ListenAddr)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("监听地址必须是 IPv4 地址")
		}
	}
	if !IsValidHost(r.TargetHost) {
		return fmt.Errorf("目标地址 %q 格式不正确", r.TargetHost)
	}
	switch r.Backend {
	case BackendSocat:
	case BackendNft:
		if IsIPv6(r.TargetHost) {
			return fmt.Errorf("nftables 后端暂不支持 IPv6 目标，请使用 socat 后端")
		}
	default:
		return fmt.Errorf("后端必须是 socat 或 nft")
	}
	return ValidateObfs(r.Protocol, r.Obfs)
}

// ValidateRules 校验一组规则，包括同一节点上的端口冲突。
func ValidateRules(rules []Rule, reservedTCPPort int) error {
	ids := map[string]bool{}
	ports := map[string]string{}
	for i := range rules {
		r := &rules[i]
		if err := ValidateRule(r); err != nil {
			return fmt.Errorf("规则 %s: %w", ruleLabel(r), err)
		}
		if ids[r.ID] {
			return fmt.Errorf("规则 ID 重复: %s", r.ID)
		}
		ids[r.ID] = true
		if r.Protocol == ProtoTCP && r.ListenPort == reservedTCPPort {
			return fmt.Errorf("规则 %s: 监听端口 %d 与节点管理端口冲突", ruleLabel(r), r.ListenPort)
		}
		key := fmt.Sprintf("%s/%d", r.Protocol, r.ListenPort)
		if other, ok := ports[key]; ok {
			return fmt.Errorf("规则 %s 与 %s 的监听端口 %s 冲突", ruleLabel(r), other, key)
		}
		ports[key] = ruleLabel(r)
	}
	return nil
}

func ruleLabel(r *Rule) string {
	if r.Name != "" {
		return r.Name
	}
	return r.ID
}
