package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"mocat/internal/api"
	"mocat/internal/node/obfs"
)

// ErrStaleConfig 下发的配置版本不比当前新（A-06）。
var ErrStaleConfig = errors.New("配置版本不比当前版本新")

type groupRT struct {
	key      string
	plugin   obfs.Plugin
	obfs     api.Obfs
	idx      int
	queue    int
	mark     uint32
	proc     *Proc
	refs     int
	stateDir string
}

func (g *groupRT) env() obfs.GroupEnv {
	return obfs.GroupEnv{Queue: g.queue, Mark: g.mark, Mask: markMask, StateDir: g.stateDir, Index: g.idx}
}

func (g *groupRT) healthy(q map[int]queueInfo) bool {
	_, bound := q[g.queue]
	return g.proc.Running() && bound
}

type ruleRT struct {
	rule   api.Rule
	spec   string
	ip     string
	slot   int
	group  *groupRT
	socat  *Proc
	failed string // 非空表示规则未能启用
}

func (r *ruleRT) active() bool { return r.slot > 0 && r.failed == "" }

// Manager 负责把下发的配置落实为转发进程、伪装进程和 nftables 规则。
type Manager struct {
	mu      sync.Mutex
	cfg     *Config
	env     *Env
	plugins obfs.Registry
	log     *slog.Logger

	current  api.NodeConfig
	rules    map[string]*ruleRT
	groups   map[string]*groupRT
	slotUsed [maxSlots + 1]bool
	nextSlot int
	grpUsed  [maxSlots + 1]bool
	sysctls  map[string]string // 修改过的 sysctl 原值，退出时恢复
	ctWarned bool
}

// NewManager 创建管理器。
func NewManager(cfg *Config, env *Env, log *slog.Logger) *Manager {
	return &Manager{
		cfg: cfg, env: env, log: log,
		plugins: obfs.Registry{
			api.ObfsFakeHTTP: &obfs.Fake{Type: api.ObfsFakeHTTP, Bin: env.FakeHTTP},
			api.ObfsFakeSIP:  &obfs.Fake{Type: api.ObfsFakeSIP, Bin: env.FakeSIP},
		},
		rules:   map[string]*ruleRT{},
		groups:  map[string]*groupRT{},
		sysctls: map[string]string{},
	}
}

func (m *Manager) cachePath() string { return filepath.Join(m.cfg.StateDir, "config.json") }

// LoadCache 读取本地缓存的最后一次配置（N-05）。
func (m *Manager) LoadCache() (*api.NodeConfig, error) {
	b, err := os.ReadFile(m.cachePath())
	if err != nil {
		return nil, err
	}
	var c api.NodeConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (m *Manager) saveCache(c api.NodeConfig) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := m.cachePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.cachePath())
}

// Current 当前配置。
func (m *Manager) Current() api.NodeConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// Apply 应用新配置。fromCache 为 true 时用于启动恢复，不做版本比较也不重写缓存。
func (m *Manager) Apply(c api.NodeConfig, fromCache bool) error {
	if err := api.ValidateRules(c.Rules, m.cfg.ManagementPort()); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !fromCache {
		if c.Version <= m.current.Version {
			return ErrStaleConfig
		}
		if err := m.saveCache(c); err != nil {
			m.log.Error("保存配置缓存失败", "err", err)
		}
	}
	m.current = c
	m.log.Info("应用配置", "version", c.Version, "rules", len(c.Rules), "from_cache", fromCache)
	m.reconcileLocked()
	return nil
}

// Run 周期性重新解析域名、重试失败的规则。
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.Lock()
			m.reconcileLocked()
			m.mu.Unlock()
		}
	}
}

type rulePlan struct {
	rule api.Rule
	ip   string
	spec string
	err  string
}

func (m *Manager) resolve(r api.Rule, old string) (string, error) {
	if ip := net.ParseIP(r.TargetHost); ip != nil {
		return ip.String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", r.TargetHost)
	if err != nil || len(ips) == 0 {
		if old != "" {
			return old, nil // 解析暂时失败时继续使用上次结果
		}
		return "", fmt.Errorf("域名 %s 解析失败: %v", r.TargetHost, err)
	}
	var v4, v6 []string
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	// socat 可以在两个协议族之间转换，优先 IPv4；nft 后端不能转换，监听地址限定了协议族时只能取同族地址。
	fam := 0
	if r.Backend == api.BackendNft {
		fam = api.ListenFamily(r.ListenAddr)
	}
	var cands []string
	switch fam {
	case 4:
		cands = v4
	case 6:
		cands = v6
	default:
		cands = append(v4, v6...)
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("域名 %s 没有可用的 IPv%d 地址（nftables 后端不能在 IPv4 与 IPv6 之间转换）", r.TargetHost, fam)
	}
	for _, c := range cands {
		if c == old {
			return old, nil // 轮询 DNS 下避免无谓重启
		}
	}
	return cands[0], nil
}

func specOf(r api.Rule, ip string) string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(append(b, []byte("|"+ip)...))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) checkDeps(r api.Rule) string {
	if !m.env.Root {
		if a, n := hasCaps(); !a || !n {
			return "节点缺少 root / CAP_NET_ADMIN / CAP_NET_RAW 权限"
		}
	}
	switch r.Backend {
	case api.BackendSocat:
		if m.env.Socat == "" {
			return "socat 不可用"
		}
	case api.BackendNft:
		if m.env.Nft == "" {
			return "nft 不可用"
		}
	}
	if r.Obfs.Type != "" && r.Obfs.Type != api.ObfsNone {
		if m.env.Nft == "" {
			return "nft 不可用，无法启用伪装"
		}
		if !m.env.HasQueue {
			return "内核不支持 NFQUEUE，无法启用伪装"
		}
		p, err := m.plugins.Get(r.Obfs.Type)
		if err != nil {
			return err.Error()
		}
		if p.Binary() == "" {
			return "未找到 " + p.Name() + " 程序"
		}
	}
	return ""
}

func (m *Manager) allocSlot() int {
	for i := 0; i < maxSlots; i++ {
		s := (m.nextSlot+i)%maxSlots + 1
		if !m.slotUsed[s] {
			m.slotUsed[s] = true
			m.nextSlot = s
			return s
		}
	}
	return 0
}

func (m *Manager) setSysctl(name, val string) error {
	old, err := setSysctl(name, val)
	if err != nil {
		return err
	}
	if old != val {
		if _, ok := m.sysctls[name]; !ok {
			m.sysctls[name] = old
		}
		m.log.Info("已修改 sysctl", "name", name, "value", val, "old", old)
	}
	return nil
}

// enableForwarding 为 nft 后端开启对应协议族的转发。
func (m *Manager) enableForwarding(v6 bool) error {
	if !v6 {
		return m.setSysctl("net.ipv4.ip_forward", "1")
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding"); err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	// 开启 IPv6 转发后，accept_ra=1 的接口不再接受路由通告，靠 RA 获得默认路由的节点会断掉 IPv6。
	// 先把这些接口（含 default，影响之后新建的接口）改为 2（转发时仍接受），退出时与 forwarding 一起恢复。
	paths, _ := filepath.Glob("/proc/sys/net/ipv6/conf/*/accept_ra")
	for _, p := range paths {
		ifname := filepath.Base(filepath.Dir(p))
		if ifname == "all" || ifname == "lo" {
			continue
		}
		if b, err := os.ReadFile(p); err != nil || strings.TrimSpace(string(b)) != "1" {
			continue
		}
		// sysctl 名中接口名里的 “.” 写作 “/”。
		if err := m.setSysctl("net.ipv6.conf."+strings.ReplaceAll(ifname, ".", "/")+".accept_ra", "2"); err != nil {
			return err
		}
	}
	return m.setSysctl("net.ipv6.conf.all.forwarding", "1")
}

// acquireGroup 获取（必要时启动）伪装进程，并等待其就绪（队列已绑定）。
func (m *Manager) acquireGroup(o api.Obfs) (*groupRT, error) {
	p, err := m.plugins.Get(o.Type)
	if err != nil {
		return nil, err
	}
	key, err := p.GroupKey(o)
	if err != nil {
		return nil, err
	}
	if g, ok := m.groups[key]; ok {
		g.refs++
		return g, nil
	}
	if o.Type == api.ObfsFakeSIP {
		// FakeSIP 规则依赖 ct 报文计数来截住每个流的前几个报文。
		if err := m.setSysctl("net.netfilter.nf_conntrack_acct", "1"); err != nil {
			return nil, err
		}
	}
	idx := 0
	for i := 1; i <= maxSlots; i++ {
		if !m.grpUsed[i] {
			idx = i
			break
		}
	}
	if idx == 0 {
		return nil, fmt.Errorf("伪装进程数量已达上限")
	}
	g := &groupRT{key: key, plugin: p, obfs: o, idx: idx, queue: queueBase + idx, mark: procMark(idx), stateDir: m.cfg.StateDir}
	args, err := p.Command(o, g.env())
	if err != nil {
		return nil, err
	}
	g.proc = NewProc(fmt.Sprintf("%s#%d", p.Name(), idx), p.Binary(), args, m.log)
	g.proc.Start()
	// N-28：确认伪装进程就绪后才安装 NFQUEUE 规则和开启转发。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if g.healthy(readQueues()) {
			m.grpUsed[idx] = true
			g.refs = 1
			m.groups[key] = g
			m.log.Info("伪装进程就绪", "type", p.Name(), "queue", g.queue, "mark", fmt.Sprintf("0x%08x", g.mark))
			return g, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	reason := g.proc.LastError()
	g.proc.Stop()
	if reason == "" {
		reason = "5 秒内未绑定队列"
	}
	return nil, fmt.Errorf("%s 进程未就绪: %s", p.Name(), reason)
}

func (m *Manager) releaseRule(rt *ruleRT) {
	if rt.slot > 0 {
		m.slotUsed[rt.slot] = false
		rt.slot = 0
	}
	if rt.group != nil {
		rt.group.refs--
		rt.group = nil
	}
}

func (m *Manager) applyNftLocked() error {
	if m.env.Nft == "" {
		return nil
	}
	var rules []nftRule
	for _, rt := range m.rules {
		if rt.active() {
			rules = append(rules, nftRule{rule: rt.rule, ip: rt.ip, mark: ruleMark(rt.slot), group: rt.group})
		}
	}
	var groups []*groupRT
	for _, g := range m.groups {
		if g.refs > 0 {
			groups = append(groups, g)
		}
	}
	counters, _ := nftCounters(m.env.Nft)
	return nftApply(m.env.Nft, buildRuleset(rules, groups, counters, m.env.HasFib))
}

func (m *Manager) conntrackDelete(args ...string) {
	if m.env.Conntrack == "" {
		if !m.ctWarned {
			m.log.Warn("未安装 conntrack 命令，无法清理规则相关的已有连接（N-2A）")
			m.ctWarned = true
		}
		return
	}
	// conntrack 默认只操作 IPv4 表，两个协议族分别清理。没有匹配条目时返回非零，忽略。
	for _, f := range []string{"ipv4", "ipv6"} {
		_ = exec.Command(m.env.Conntrack, append([]string{"-D", "-f", f}, args...)...).Run()
	}
}

// isAnyAddr 监听地址是否表示“所有地址”（空、0.0.0.0、::）。
func isAnyAddr(addr string) bool {
	if addr == "" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsUnspecified()
}

// socatArgs 生成 socat 参数。socat 在两端各自建立套接字，监听与目标可以是不同的协议族（IPv4 / IPv6 互转）。
// 监听地址为空时，若本机启用了 IPv6 则双栈监听（ipv6only=0，IPv4 客户端以映射地址接入），否则只监听 IPv4。
func socatArgs(r api.Rule, ip string, hasIPv6 bool) []string {
	v := "4"
	tgt := ip
	if api.IsIPv6(ip) {
		v = "6"
		tgt = "[" + ip + "]"
	}
	lv := "4"
	listenOpts := ""
	switch api.ListenFamily(r.ListenAddr) {
	case 0:
		if hasIPv6 {
			lv, listenOpts = "6", ",ipv6only=0"
		}
	case 4:
		if !isAnyAddr(r.ListenAddr) {
			listenOpts = ",bind=" + r.ListenAddr
		}
	case 6:
		lv, listenOpts = "6", ",ipv6only=1"
		if !isAnyAddr(r.ListenAddr) {
			listenOpts += ",bind=[" + r.ListenAddr + "]"
		}
	}
	listenOpts += ",reuseaddr,fork"
	if r.Protocol == api.ProtoTCP {
		return []string{
			fmt.Sprintf("TCP%s-LISTEN:%d%s", lv, r.ListenPort, listenOpts),
			fmt.Sprintf("TCP%s:%s:%d", v, tgt, r.TargetPort),
		}
	}
	return []string{
		"-T", "120",
		fmt.Sprintf("UDP%s-LISTEN:%d%s", lv, r.ListenPort, listenOpts),
		fmt.Sprintf("UDP%s:%s:%d", v, tgt, r.TargetPort),
	}
}

// reconcileLocked 让运行状态与 m.current 一致。只有新增、删除、变化的规则会被触动（N-15）。
// 启用顺序：伪装进程就绪 → nft（队列 + 计数 + DNAT）→ socat；停止顺序相反（N-28）。
func (m *Manager) reconcileLocked() {
	plans := map[string]rulePlan{}
	for _, r := range m.current.Rules {
		if !r.Enabled {
			continue
		}
		old := ""
		if rt, ok := m.rules[r.ID]; ok {
			old = rt.ip
		}
		p := rulePlan{rule: r}
		ip, err := m.resolve(r, old)
		if err != nil {
			p.err = err.Error()
		}
		p.ip = ip
		p.spec = specOf(r, ip)
		plans[r.ID] = p
	}

	// 1. 找出需要停止的规则（已删除、已停用、参数变化、上次失败需重试）
	var stopping []*ruleRT
	for id, rt := range m.rules {
		p, ok := plans[id]
		if ok && p.spec == rt.spec && rt.failed == "" {
			continue
		}
		stopping = append(stopping, rt)
		delete(m.rules, id)
	}
	// 先停转发
	for _, rt := range stopping {
		if rt.socat != nil {
			rt.socat.Stop()
			rt.socat = nil
		}
	}
	var oldMarks []uint32
	for _, rt := range stopping {
		if rt.active() {
			oldMarks = append(oldMarks, ruleMark(rt.slot))
		}
		m.releaseRule(rt)
	}

	// 2. 准备新规则：分配标记、启动并等待伪装进程就绪
	var added []*ruleRT
	for id, p := range plans {
		if _, ok := m.rules[id]; ok {
			continue
		}
		rt := &ruleRT{rule: p.rule, spec: p.spec, ip: p.ip}
		m.rules[id] = rt
		if p.err != "" {
			rt.failed = p.err
			continue
		}
		if reason := m.checkDeps(p.rule); reason != "" {
			rt.failed = reason
			continue
		}
		if p.rule.Backend == api.BackendNft {
			if err := m.enableForwarding(api.IsIPv6(p.ip)); err != nil {
				rt.failed = err.Error()
				continue
			}
		}
		rt.slot = m.allocSlot()
		if rt.slot == 0 {
			rt.failed = "规则数量已达上限"
			continue
		}
		if p.rule.Obfs.Type != "" && p.rule.Obfs.Type != api.ObfsNone {
			g, err := m.acquireGroup(p.rule.Obfs)
			if err != nil {
				rt.failed = err.Error()
				m.releaseRule(rt)
				continue
			}
			rt.group = g
		}
		added = append(added, rt)
	}

	// 3. 原子替换 nft 规则集
	if err := m.applyNftLocked(); err != nil {
		m.log.Error("应用 nft 规则失败", "err", err)
		for _, rt := range added {
			rt.failed = err.Error()
			m.releaseRule(rt)
		}
		added = nil
		if err2 := m.applyNftLocked(); err2 != nil {
			m.log.Error("回退 nft 规则失败", "err", err2)
		}
	}

	// 4. 清理与变更规则相关的已有连接（N-2A）
	for _, mk := range oldMarks {
		m.conntrackDelete("--mark", fmt.Sprintf("%d/%d", mk, markMask))
	}
	for _, rt := range added {
		if rt.rule.Backend == api.BackendNft {
			m.conntrackDelete("-p", rt.rule.Protocol, "--orig-port-dst", strconv.Itoa(rt.rule.ListenPort))
		}
	}

	// 5. 最后开启 socat 转发
	for _, rt := range added {
		if rt.rule.Backend == api.BackendSocat {
			rt.socat = NewProc("socat:"+rt.rule.ID, m.env.Socat, socatArgs(rt.rule, rt.ip, m.env.HasIPv6), m.log)
			rt.socat.SetGID(socatGID(ruleMark(rt.slot)))
			rt.socat.Start()
		}
		m.log.Info("规则已启用", "rule", rt.rule.ID, "proto", rt.rule.Protocol, "listen", rt.rule.ListenPort,
			"target", net.JoinHostPort(rt.ip, strconv.Itoa(rt.rule.TargetPort)), "backend", rt.rule.Backend, "obfs", rt.rule.Obfs.Type)
	}
	for _, rt := range m.rules {
		if rt.failed != "" {
			m.log.Warn("规则启用失败", "rule", rt.rule.ID, "reason", rt.failed)
		}
	}

	// 6. 撤掉不再使用的伪装进程（其队列规则已在第 3 步移除）
	for key, g := range m.groups {
		if g.refs <= 0 {
			g.proc.Stop()
			m.grpUsed[g.idx] = false
			delete(m.groups, key)
		}
	}
}

// Shutdown 退出清理（N-06）：先停转发，再删 nft 表，再停伪装进程，最后恢复 sysctl。
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, rt := range m.rules {
		if rt.socat != nil {
			rt.socat.Stop()
		}
	}
	if err := nftDeleteTable(m.env.Nft); err != nil {
		m.log.Error("删除 nft 表失败", "err", err)
	}
	for _, g := range m.groups {
		g.proc.Stop()
	}
	for name, old := range m.sysctls {
		if _, err := setSysctl(name, old); err != nil {
			m.log.Warn("恢复 sysctl 失败", "name", name, "err", err)
		}
	}
	m.rules = map[string]*ruleRT{}
	m.groups = map[string]*groupRT{}
}

// Status 返回每条规则的运行状态（N-61）。
func (m *Manager) Status() []api.RuleStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := readQueues()
	var out []api.RuleStatus
	for _, r := range m.current.Rules {
		s := api.RuleStatus{ID: r.ID}
		rt := m.rules[r.ID]
		switch {
		case !r.Enabled:
			s.State = api.StateDisabled
		case rt == nil:
			s.State = api.StatePending
		case rt.failed != "":
			s.State, s.Reason = api.StateFailed, rt.failed
		case rt.group != nil && !rt.group.healthy(q):
			s.State = api.StateFailed
			s.Reason = "伪装进程未运行，该规则流量已被阻断，正在自动重启"
			if e := rt.group.proc.LastError(); e != "" {
				s.Reason += "（" + e + "）"
			}
		case rt.socat != nil && !rt.socat.Running():
			s.State = api.StateFailed
			s.Reason = "socat 进程异常退出，正在自动重启"
			if e := rt.socat.LastError(); e != "" {
				s.Reason += "（" + e + "）"
			}
		default:
			s.State = api.StateRunning
		}
		if rt != nil {
			s.ResolvedIP = rt.ip
		}
		out = append(out, s)
	}
	return out
}

// Stats 返回每条规则的流量统计（N-62）。
func (m *Manager) Stats() []api.RuleStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	counters, _ := nftCounters(m.env.Nft)
	conns := countConns(m.env.Conntrack)
	q := readQueues()
	var out []api.RuleStats
	for _, r := range m.current.Rules {
		s := api.RuleStats{ID: r.ID}
		up := counters[counterName(r.ID, "up")]
		down := counters[counterName(r.ID, "down")]
		s.UpBytes, s.UpPackets = up.Bytes, up.Packets
		s.DownBytes, s.DownPackets = down.Bytes, down.Packets
		if rt := m.rules[r.ID]; rt != nil && rt.active() {
			s.Conns = conns[ruleMark(rt.slot)]
			if rt.group != nil {
				if qi, ok := q[rt.group.queue]; ok {
					s.Blocked = qi.QueueDrop + qi.UserDropped
				}
			}
		}
		out = append(out, s)
	}
	return out
}
