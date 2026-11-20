package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"mocat/internal/api"
)

// RuleView 规则及其运行状态。
type RuleView struct {
	Rule
	Source     string        `json:"source"` // rule / chain
	ChainID    string        `json:"chain_id,omitempty"`
	Hop        int           `json:"hop"`
	NodeName   string        `json:"node_name"`
	Resolved   api.Rule      `json:"resolved"` // 展开模板后下发到节点的规则
	State      string        `json:"state"`
	Reason     string        `json:"reason,omitempty"`
	ResolvedIP string        `json:"resolved_ip,omitempty"`
	Stats      api.RuleStats `json:"stats"`
	Rate       Rate          `json:"rate"`
}

func (s *Server) ruleViews(n Node, compiled []CompiledRule) []RuleView {
	rt := s.syncer.Runtime(n.ID)
	stored := map[string]Rule{}
	if rules, err := s.store.Rules(); err == nil {
		for _, r := range rules {
			stored[r.ID] = r
		}
	}
	out := []RuleView{}
	for _, c := range compiled {
		v := RuleView{NodeName: n.Name, Resolved: c.Rule, ChainID: c.ChainID, Hop: c.Hop}
		if c.ChainID != "" {
			v.Source = "chain"
			v.Rule = Rule{ID: c.ID, NodeID: n.ID, Name: c.Name, Enabled: c.Enabled, Protocol: c.Protocol, ListenPort: c.ListenPort,
				TargetHost: c.TargetHost, TargetPort: c.TargetPort, Backend: c.Backend, Obfs: ObfsRef{Type: c.Obfs.Type, Params: c.Obfs.Params}}
		} else {
			v.Source = "rule"
			v.Rule = stored[c.ID]
		}
		v.State, v.Reason = s.ruleState(n, rt, c.ID, c.Enabled)
		if rt.Status != nil {
			for _, st := range rt.Status.Rules {
				if st.ID == c.ID {
					v.ResolvedIP = st.ResolvedIP
				}
			}
		}
		v.Stats = rt.Stats[c.ID]
		v.Rate = rt.Rates[c.ID]
		out = append(out, v)
	}
	return out
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	world, compiled, err := s.compiled()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	out := []RuleView{}
	for id, n := range world.Nodes {
		if nodeID != "" && id != nodeID {
			continue
		}
		out = append(out, s.ruleViews(n, compiled[id])...)
	}
	writeJSON(w, http.StatusOK, out)
}

func normalizeObfs(proto string, o *ObfsRef) {
	o.Type = strings.TrimSpace(o.Type)
	if o.Type == "" {
		o.Type = api.ObfsNone
	}
	if o.Type == api.ObfsNone {
		o.Params, o.TemplateID = nil, ""
	}
	if o.TemplateID != "" {
		o.Params = nil
	}
	if len(o.Params) > 0 && string(o.Params) == "null" {
		o.Params = nil
	}
}

func (s *Server) handleSaveRule(w http.ResponseWriter, r *http.Request) {
	var in Rule
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	world, err := s.store.LoadWorld()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	id := r.PathValue("id")
	now := time.Now().Unix()
	if id == "" {
		in.ID = "r" + RandToken(5)
		in.Created = now
	} else {
		old, err := s.store.Rule(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "规则不存在")
			return
		}
		in.ID, in.Created = id, old.Created
		if in.NodeID != old.NodeID {
			writeErr(w, http.StatusBadRequest, "不能修改规则所属节点")
			return
		}
	}
	in.Updated = now
	in.Name = strings.TrimSpace(in.Name)
	in.TargetHost = strings.TrimSpace(in.TargetHost)
	in.ListenAddr = strings.TrimSpace(in.ListenAddr)
	if in.Backend == "" {
		in.Backend = api.BackendSocat
	}
	if in.Name == "" {
		in.Name = fmt.Sprintf("%s-%d", in.Protocol, in.ListenPort)
	}
	normalizeObfs(in.Protocol, &in.Obfs)
	if _, ok := world.Nodes[in.NodeID]; !ok {
		writeErr(w, http.StatusBadRequest, "所选节点不存在")
		return
	}
	replaced := false
	for i := range world.Rules {
		if world.Rules[i].ID == in.ID {
			world.Rules[i], replaced = in, true
		}
	}
	if !replaced {
		world.Rules = append(world.Rules, in)
	}
	if _, err := world.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PutRule(in); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.syncer.BumpVersions()
	act := "新建规则"
	if id != "" {
		act = "修改规则"
	}
	b, _ := json.Marshal(in)
	s.audit(r, act, string(b))
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := s.store.Rule(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "规则不存在")
		return
	}
	if err := s.store.DeleteRule(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.syncer.BumpVersions()
	s.audit(r, "删除规则", fmt.Sprintf("%s (%s/%d)", old.Name, old.Protocol, old.ListenPort))
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// ---- 转发链 ----

// HopView 链中一跳的状态。
type HopView struct {
	Hop
	NodeName   string `json:"node_name"`
	Online     bool   `json:"online"`
	RuleID     string `json:"rule_id"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	Blocked    uint64 `json:"blocked"`
}

// ChainView 链及其整体状态（C-25）。
type ChainView struct {
	Chain
	HopViews  []HopView `json:"hop_views"`
	State     string    `json:"state"` // running / failed / disabled / syncing
	UpBytes   uint64    `json:"up_bytes"`
	DownBytes uint64    `json:"down_bytes"`
	Conns     int       `json:"conns"`
	Rate      Rate      `json:"rate"`
	Entry     string    `json:"entry"`
}

func (s *Server) chainView(world *World, c Chain) ChainView {
	v := ChainView{Chain: c, State: api.StateRunning}
	if !c.Enabled {
		v.State = api.StateDisabled
	}
	rules, _ := world.compileChain(c)
	for i, h := range c.Hops {
		n := world.Nodes[h.NodeID]
		rt := s.syncer.Runtime(h.NodeID)
		hv := HopView{Hop: h, NodeName: n.Name, Online: rt.Online, RuleID: ChainRuleID(c.ID, i)}
		if i < len(rules) {
			hv.TargetHost, hv.TargetPort = rules[i].TargetHost, rules[i].TargetPort
		}
		hv.State, hv.Reason = s.ruleState(n, rt, hv.RuleID, c.Enabled)
		hv.Blocked = rt.Stats[hv.RuleID].Blocked
		// 链中任一节点失败 / 离线即整体失败；否则有未同步的跳则为同步中
		if c.Enabled {
			switch hv.State {
			case api.StateRunning:
			case "syncing", api.StatePending:
				if v.State == api.StateRunning {
					v.State = "syncing"
				}
			default:
				v.State = api.StateFailed
			}
		}
		if i == 0 {
			st := rt.Stats[hv.RuleID]
			v.UpBytes, v.DownBytes, v.Conns = st.UpBytes, st.DownBytes, st.Conns
			v.Rate = rt.Rates[hv.RuleID]
			v.Entry = fmt.Sprintf("%s:%d", n.DataAddr(), h.ListenPort)
		}
		v.HopViews = append(v.HopViews, hv)
	}
	return v
}

func (s *Server) handleListChains(w http.ResponseWriter, r *http.Request) {
	world, err := s.store.LoadWorld()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := []ChainView{}
	for _, c := range world.Chains {
		out = append(out, s.chainView(world, c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSaveChain(w http.ResponseWriter, r *http.Request) {
	var in Chain
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	world, err := s.store.LoadWorld()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	id := r.PathValue("id")
	now := time.Now().Unix()
	if id == "" {
		in.ID = "c" + RandToken(5)
		in.Created = now
	} else {
		old, err := s.store.Chain(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "转发链不存在")
			return
		}
		in.ID, in.Created = id, old.Created
	}
	in.Updated = now
	in.Name = strings.TrimSpace(in.Name)
	in.TargetHost = strings.TrimSpace(in.TargetHost)
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "请填写链名称")
		return
	}
	if len(in.Hops) == 0 {
		writeErr(w, http.StatusBadRequest, "至少选择一个节点")
		return
	}
	if !api.IsValidHost(in.TargetHost) || in.TargetPort < 1 || in.TargetPort > 65535 {
		writeErr(w, http.StatusBadRequest, "最终目标地址或端口不正确")
		return
	}
	// 先放入其他链 / 规则后的世界视图，再为端口为 0 的跳自动分配中转端口（C-21）
	var others []Chain
	for _, c := range world.Chains {
		if c.ID != in.ID {
			others = append(others, c)
		}
	}
	world.Chains = others
	for i := range in.Hops {
		h := &in.Hops[i]
		if h.Backend == "" {
			h.Backend = api.BackendSocat
		}
		normalizeObfs(in.Protocol, &h.Obfs)
		if _, ok := world.Nodes[h.NodeID]; !ok {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("第 %d 跳的节点不存在", i+1))
			return
		}
	}
	for i := range in.Hops {
		h := &in.Hops[i]
		if h.ListenPort != 0 {
			continue
		}
		used := world.UsedPorts(h.NodeID, in.Protocol, "")
		for j, o := range in.Hops {
			if j != i && o.NodeID == h.NodeID {
				used[o.ListenPort] = true
			}
		}
		for p := 20000; p < 30000; p++ {
			if !used[p] {
				h.ListenPort = p
				break
			}
		}
		if h.ListenPort == 0 {
			writeErr(w, http.StatusBadRequest, "无法自动分配端口")
			return
		}
	}
	world.Chains = append(world.Chains, in)
	if _, err := world.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PutChain(in); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.syncer.BumpVersions()
	act := "新建转发链"
	if id != "" {
		act = "修改转发链"
	}
	b, _ := json.Marshal(in)
	s.audit(r, act, string(b))
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handleDeleteChain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old, err := s.store.Chain(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "转发链不存在")
		return
	}
	if err := s.store.DeleteChain(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.syncer.BumpVersions()
	s.audit(r, "删除转发链", old.Name)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// ---- 伪装模板 ----

func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.Templates()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ts)
}

func (s *Server) handleSaveTemplate(w http.ResponseWriter, r *http.Request) {
	var in Template
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	if id != "" {
		old, err := s.store.Template(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, "模板不存在")
			return
		}
		if old.Builtin {
			writeErr(w, http.StatusBadRequest, "内置模板不能修改")
			return
		}
		if old.Type != in.Type {
			writeErr(w, http.StatusBadRequest, "不能修改模板类型")
			return
		}
		in.ID = id
	} else {
		in.ID = "t" + RandToken(5)
	}
	in.Builtin = false
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeErr(w, http.StatusBadRequest, "请填写模板名称")
		return
	}
	proto := api.ProtoTCP
	if in.Type == api.ObfsFakeSIP {
		proto = api.ProtoUDP
	} else if in.Type != api.ObfsFakeHTTP {
		writeErr(w, http.StatusBadRequest, "模板类型必须是 fakehttp 或 fakesip")
		return
	}
	p, _ := json.Marshal(in.Params)
	if err := api.ValidateObfs(proto, api.Obfs{Type: in.Type, Params: p}); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.PutTemplate(in); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.syncer.BumpVersions()
	s.audit(r, "保存伪装模板", in.Name)
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := s.store.Template(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "模板不存在")
		return
	}
	if t.Builtin {
		writeErr(w, http.StatusBadRequest, "内置模板不能删除")
		return
	}
	world, err := s.store.LoadWorld()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, r := range world.Rules {
		if r.Obfs.TemplateID == id {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("模板被规则「%s」引用", r.Name))
			return
		}
	}
	for _, c := range world.Chains {
		for _, h := range c.Hops {
			if h.Obfs.TemplateID == id {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("模板被转发链「%s」引用", c.Name))
				return
			}
		}
	}
	if err := s.store.DeleteTemplate(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "删除伪装模板", t.Name)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// ---- 总览（C-50） ----

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	world, compiled, err := s.compiled()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var out struct {
		Nodes       int     `json:"nodes"`
		Online      int     `json:"online"`
		Rules       int     `json:"rules"`
		FailedRules int     `json:"failed_rules"`
		Chains      int     `json:"chains"`
		FailedChain int     `json:"failed_chains"`
		UpBytes     uint64  `json:"up_bytes"`
		DownBytes   uint64  `json:"down_bytes"`
		RateUp      float64 `json:"rate_up"`
		RateDown    float64 `json:"rate_down"`
		Conns       int     `json:"conns"`
		Problems    []struct {
			Kind, Name, Reason string
		} `json:"problems"`
	}
	add := func(kind, name, reason string) {
		out.Problems = append(out.Problems, struct{ Kind, Name, Reason string }{kind, name, reason})
	}
	for id, n := range world.Nodes {
		out.Nodes++
		v := s.nodeView(n, compiled[id])
		if v.Runtime.Online {
			out.Online++
		} else {
			add("节点离线", n.Name, v.Runtime.LastError)
		}
		if v.Runtime.FPAlert != "" {
			add("证书变化", n.Name, "节点证书指纹已变化，已拒绝连接")
		}
		out.Rules += v.RuleCount
		out.FailedRules += v.FailedRules
		out.UpBytes += v.UpBytes
		out.DownBytes += v.DownBytes
		out.RateUp += v.RateUp
		out.RateDown += v.RateDown
		out.Conns += v.Conns
		rt := s.syncer.Runtime(id)
		for _, c := range compiled[id] {
			st, reason := s.ruleState(n, rt, c.ID, c.Enabled)
			if st == api.StateFailed {
				add("规则异常", n.Name+" / "+c.Name, reason)
			}
		}
	}
	for _, c := range world.Chains {
		out.Chains++
		if v := s.chainView(world, c); v.State == api.StateFailed {
			out.FailedChain++
		}
	}
	writeJSON(w, http.StatusOK, out)
}
