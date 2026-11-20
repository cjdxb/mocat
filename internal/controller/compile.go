package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"mocat/internal/api"
)

// World 一次性读取的全部配置，用于编译和校验。
type World struct {
	Nodes     map[string]Node
	Rules     []Rule
	Chains    []Chain
	Templates map[string]Template
}

// LoadWorld 从存储读取全部配置。
func (s *Store) LoadWorld() (*World, error) {
	w := &World{Nodes: map[string]Node{}, Templates: map[string]Template{}}
	ns, err := s.Nodes()
	if err != nil {
		return nil, err
	}
	for _, n := range ns {
		w.Nodes[n.ID] = n
	}
	if w.Rules, err = s.Rules(); err != nil {
		return nil, err
	}
	if w.Chains, err = s.Chains(); err != nil {
		return nil, err
	}
	ts, err := s.Templates()
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		w.Templates[t.ID] = t
	}
	return w, nil
}

// resolveObfs 把引用模板的伪装配置展开为具体参数。
func (w *World) resolveObfs(o ObfsRef) (api.Obfs, error) {
	if o.Type == "" || o.Type == api.ObfsNone {
		return api.Obfs{Type: api.ObfsNone}, nil
	}
	if o.TemplateID != "" {
		t, ok := w.Templates[o.TemplateID]
		if !ok {
			return api.Obfs{}, fmt.Errorf("伪装模板 %s 不存在", o.TemplateID)
		}
		if t.Type != o.Type {
			return api.Obfs{}, fmt.Errorf("伪装模板「%s」类型为 %s，与所选伪装方式不符", t.Name, t.Type)
		}
		b, _ := json.Marshal(t.Params)
		return api.Obfs{Type: o.Type, Params: b}, nil
	}
	return api.Obfs{Type: o.Type, Params: o.Params}, nil
}

// CompiledRule 编译出的规则及其来源。
type CompiledRule struct {
	api.Rule
	NodeID  string
	ChainID string
	Hop     int
}

// Compile 把单节点规则和转发链展开为每个节点的规则列表。
func (w *World) Compile() (map[string][]CompiledRule, error) {
	out := map[string][]CompiledRule{}
	for _, r := range w.Rules {
		if _, ok := w.Nodes[r.NodeID]; !ok {
			continue
		}
		o, err := w.resolveObfs(r.Obfs)
		if err != nil {
			return nil, fmt.Errorf("规则「%s」: %w", r.Name, err)
		}
		out[r.NodeID] = append(out[r.NodeID], CompiledRule{NodeID: r.NodeID, Rule: api.Rule{
			ID: r.ID, Name: r.Name, Enabled: r.Enabled, Protocol: r.Protocol,
			ListenAddr: r.ListenAddr, ListenPort: r.ListenPort,
			TargetHost: r.TargetHost, TargetPort: r.TargetPort, Backend: r.Backend, Obfs: o,
		}})
	}
	for _, c := range w.Chains {
		rules, err := w.compileChain(c)
		if err != nil {
			return nil, err
		}
		for _, cr := range rules {
			out[cr.NodeID] = append(out[cr.NodeID], cr)
		}
	}
	return out, nil
}

// compileChain 链的组装：第 i 个节点的目标 = 第 i+1 个节点的入口；最后一个节点的目标 = 最终目标。
func (w *World) compileChain(c Chain) ([]CompiledRule, error) {
	if len(c.Hops) == 0 {
		return nil, fmt.Errorf("转发链「%s」至少需要一个节点", c.Name)
	}
	var out []CompiledRule
	for i, h := range c.Hops {
		if _, ok := w.Nodes[h.NodeID]; !ok {
			return nil, fmt.Errorf("转发链「%s」第 %d 跳的节点不存在", c.Name, i+1)
		}
		o, err := w.resolveObfs(h.Obfs)
		if err != nil {
			return nil, fmt.Errorf("转发链「%s」第 %d 跳: %w", c.Name, i+1, err)
		}
		host, port := c.TargetHost, c.TargetPort
		if i+1 < len(c.Hops) {
			next := w.Nodes[c.Hops[i+1].NodeID]
			host, port = next.DataAddr(), c.Hops[i+1].ListenPort
		}
		out = append(out, CompiledRule{NodeID: h.NodeID, ChainID: c.ID, Hop: i, Rule: api.Rule{
			ID: ChainRuleID(c.ID, i), Name: fmt.Sprintf("%s#%d", c.Name, i+1), Enabled: c.Enabled,
			Protocol: c.Protocol, ListenPort: h.ListenPort, TargetHost: host, TargetPort: port,
			Backend: h.Backend, Obfs: o,
		}})
	}
	return out, nil
}

// Validate 校验全部配置（C-23）：编译后逐节点检查格式、协议与伪装匹配、端口冲突。
func (w *World) Validate() (map[string][]CompiledRule, error) {
	for _, c := range w.Chains {
		if c.Protocol != api.ProtoTCP && c.Protocol != api.ProtoUDP {
			return nil, fmt.Errorf("转发链「%s」协议必须是 TCP 或 UDP", c.Name)
		}
		for i, h := range c.Hops {
			if h.ListenPort < 1 || h.ListenPort > 65535 {
				return nil, fmt.Errorf("转发链「%s」第 %d 跳端口不合法", c.Name, i+1)
			}
		}
	}
	compiled, err := w.Compile()
	if err != nil {
		return nil, err
	}
	for nodeID, rules := range compiled {
		n := w.Nodes[nodeID]
		list := make([]api.Rule, len(rules))
		for i, r := range rules {
			list[i] = r.Rule
		}
		if err := api.ValidateRules(list, n.Port); err != nil {
			return nil, fmt.Errorf("节点「%s」: %w", n.Name, err)
		}
	}
	return compiled, nil
}

// NodeConfigHash 节点规则内容的哈希，用于判断是否需要提升配置版本。
func NodeConfigHash(rules []CompiledRule) string {
	list := make([]api.Rule, len(rules))
	for i, r := range rules {
		list[i] = r.Rule
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, _ := json.Marshal(list)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// UsedPorts 节点上已占用的端口（协议/端口），用于自动分配中转端口。
func (w *World) UsedPorts(nodeID, proto string, excludeChain string) map[int]bool {
	used := map[int]bool{}
	if n, ok := w.Nodes[nodeID]; ok && proto == api.ProtoTCP {
		used[n.Port] = true
	}
	for _, r := range w.Rules {
		if r.NodeID == nodeID && r.Protocol == proto {
			used[r.ListenPort] = true
		}
	}
	for _, c := range w.Chains {
		if c.ID == excludeChain || c.Protocol != proto {
			continue
		}
		for _, h := range c.Hops {
			if h.NodeID == nodeID {
				used[h.ListenPort] = true
			}
		}
	}
	return used
}
