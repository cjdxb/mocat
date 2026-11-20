package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"mocat/internal/api"
	"mocat/internal/node/obfs"
)

// mocat 的所有 nftables 规则都在独立的 inet mocat 表中（NF-08）。
const (
	nftTable = "mocat"
	// 标记布局：高 16 位归 mocat 使用，低 16 位保留给系统中其他程序。
	markMask     uint32 = 0xffff0000
	ruleMarkBase uint32 = 0x6d000000 // 规则连接标记：0x6dXX0000
	procMarkBase uint32 = 0x6e000000 // 伪装进程自发报文标记：0x6eXX0000
	queueBase           = 3100
	maxSlots            = 255
)

func ruleMark(slot int) uint32 { return ruleMarkBase | uint32(slot)<<16 }

// socatGIDBase socat 进程的属组 = 基数 + 规则槽位（无需在 /etc/group 中存在）。
const socatGIDBase = 1828716544 // 0x6d000000

func socatGID(mark uint32) uint32 { return socatGIDBase + (mark>>16)&0xff }
func procMark(idx int) uint32  { return procMarkBase | uint32(idx)<<16 }

var counterNameRe = regexp.MustCompile(`[^A-Za-z0-9_]`)

func counterName(ruleID, dir string) string {
	id := counterNameRe.ReplaceAllString(ruleID, "_")
	if len(id) > 60 {
		id = id[:60]
	}
	return "r_" + id + "_" + dir
}

type counterVal struct{ Packets, Bytes uint64 }

func nfproto(v6 bool) string {
	if v6 {
		return "ipv6"
	}
	return "ipv4"
}

// ipKw nft 中协议族对应的关键字（ip daddr / ip6 daddr、dnat ip / dnat ip6）。
func ipKw(v6 bool) string {
	if v6 {
		return "ip6"
	}
	return "ip"
}

// nftRule 参与生成 nft 规则集的一条活动规则。
type nftRule struct {
	rule  api.Rule
	ip    string
	mark  uint32
	group *groupRT // 可为 nil
}

// buildRuleset 生成完整规则集脚本。表先建后删再建，在一个 nft 事务内原子替换（N-15：
// 未变化的规则在替换前后完全一致，不影响其转发）。计数器带初值以保留累计流量。
func buildRuleset(rules []nftRule, groups []*groupRT, counters map[string]counterVal, hasFib bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", nftTable, nftTable)
	if len(rules) == 0 && len(groups) == 0 {
		return b.String()
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].mark < rules[j].mark })
	sort.Slice(groups, func(i, j int) bool { return groups[i].idx < groups[j].idx })

	var pre, post, out, dnat, snat, raw []string
	for _, g := range groups {
		raw = append(raw, g.plugin.GroupRules(g.obfs, g.env()).Raw...)
		// 伪装进程自己发出的报文不进入 conntrack / NAT，也不再被送入队列。
		raw = append(raw, fmt.Sprintf("meta mark and 0x%08x == 0x%08x notrack", markMask, g.mark))
		// 伪装进程放行原报文时会带上自己的 fwmark 重新注入，必须跳过，否则会再次进入队列。
		skip := fmt.Sprintf("meta mark and 0x%08x == 0x%08x accept", markMask, g.mark)
		pre = append(pre, skip)
		post = append(post, skip)
	}
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	for _, r := range rules {
		for _, dir := range []string{"up", "down"} {
			name := counterName(r.rule.ID, dir)
			c := counters[name]
			fmt.Fprintf(&b, "  counter %s { packets %d bytes %d }\n", name, c.Packets, c.Bytes)
		}
		match := fmt.Sprintf("ct mark and 0x%08x == 0x%08x", markMask, r.mark)
		setMark := fmt.Sprintf("ct mark set ct mark and 0x%08x or 0x%08x", ^markMask, r.mark)

		// 流量统计（N-62）：两种后端统一按连接标记计数。上行 = 发往目标方向，下行 = 返回方向。
		pre = append(pre, fmt.Sprintf("%s ct direction reply counter name %q", match, counterName(r.rule.ID, "down")))
		post = append(post, fmt.Sprintf("%s ct direction original counter name %q", match, counterName(r.rule.ID, "up")))

		switch r.rule.Backend {
		case api.BackendSocat:
			// socat 以每条规则独立的 GID 运行。按套接字属组识别它主动发起的出站连接，
			// 从第一个 SYN 起就打上连接标记（socat 的 setsockopt SO_MARK 在 connect 之后才生效，不能用）。
			out = append(out, fmt.Sprintf("meta skgid %d ct direction original %s", socatGID(r.mark), setMark))
		case api.BackendNft:
			// DNAT 不能改变协议族：只匹配与目标同族的报文（监听地址的协议族已在校验 / 解析时与目标一致）。
			v6 := api.IsIPv6(r.ip)
			m := fmt.Sprintf("meta nfproto %s meta l4proto %s th dport %d", nfproto(v6), r.rule.Protocol, r.rule.ListenPort)
			if !isAnyAddr(r.rule.ListenAddr) {
				m += " " + ipKw(v6) + " daddr " + r.rule.ListenAddr
			}
			if hasFib {
				m += " fib daddr type local"
			}
			tgt := r.ip
			if v6 {
				tgt = "[" + r.ip + "]"
			}
			dnat = append(dnat, fmt.Sprintf("%s %s dnat %s to %s:%d", m, setMark, ipKw(v6), tgt, r.rule.TargetPort))
			snat = append(snat, fmt.Sprintf("ct status dnat %s masquerade", match))
		}
		if r.group != nil {
			fr := r.group.plugin.Rules(obfs.RuleEnv{
				CtMark: r.mark, Mask: markMask, Backend: r.rule.Backend, Protocol: r.rule.Protocol,
				ListenPort: r.rule.ListenPort, ListenAddr: r.rule.ListenAddr, HasFib: hasFib, IPv6: api.IsIPv6(r.ip),
			}, r.group.env())
			pre = append(pre, fr.Pre...)
			post = append(post, fr.Post...)
		}
	}
	chain := func(name, typ, hook, prio string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&b, "  chain %s {\n    type %s hook %s priority %s; policy accept;\n", name, typ, hook, prio)
		for _, l := range lines {
			fmt.Fprintf(&b, "    %s\n", l)
		}
		b.WriteString("  }\n")
	}
	chain("mc_raw_out", "filter", "output", "raw", raw)
	chain("mc_pre", "filter", "prerouting", "-150", pre)
	chain("mc_out", "filter", "output", "-150", out)
	chain("mc_dnat", "nat", "prerouting", "dstnat", dnat)
	chain("mc_snat", "nat", "postrouting", "srcnat", snat)
	chain("mc_post", "filter", "postrouting", "110", post)
	b.WriteString("}\n")
	return b.String()
}

func nftApply(nft, script string) error {
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft 应用规则失败: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// nftDeleteTable 删除 mocat 表（退出清理，N-06）。
func nftDeleteTable(nft string) error {
	if nft == "" {
		return nil
	}
	return nftApply(nft, fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", nftTable, nftTable))
}

// nftCounters 读取 mocat 表中所有命名计数器。
func nftCounters(nft string) (map[string]counterVal, error) {
	res := map[string]counterVal{}
	if nft == "" {
		return res, nil
	}
	out, err := exec.Command(nft, "-j", "list", "counters", "table", "inet", nftTable).Output()
	if err != nil {
		// 表不存在
		return res, nil
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return res, err
	}
	for _, item := range doc.Nftables {
		raw, ok := item["counter"]
		if !ok {
			continue
		}
		var c struct {
			Name    string `json:"name"`
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		}
		if json.Unmarshal(raw, &c) == nil {
			res[c.Name] = counterVal{Packets: c.Packets, Bytes: c.Bytes}
		}
	}
	return res, nil
}
