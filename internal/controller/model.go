// Package controller 实现 mocat 控制端。
package controller

import (
	"encoding/json"

	"mocat/internal/api"
)

// Node 节点。
type Node struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Remark        string `json:"remark"`
	Host          string `json:"host"`      // 管理地址（IP / 域名）
	Port          int    `json:"port"`      // 管理端口
	DataHost      string `json:"data_host"` // 数据面地址（作为链中上一跳的目标），为空时使用 Host
	TokenEnc      string `json:"token_enc"` // 加密存储的 Token
	CertFP        string `json:"cert_fp"`   // 固定的证书指纹（首次连接时记录）
	ConfigVersion int64  `json:"config_version"`
	ConfigHash    string `json:"config_hash"`
	Created       int64  `json:"created"`
}

// DataAddr 数据面地址。
func (n *Node) DataAddr() string {
	if n.DataHost != "" {
		return n.DataHost
	}
	return n.Host
}

// ObfsRef 伪装配置：可以引用模板，也可以直接填写参数。
type ObfsRef struct {
	Type       string          `json:"type"`
	Params     json.RawMessage `json:"params,omitempty"`
	TemplateID string          `json:"template_id,omitempty"`
}

// Rule 单节点规则（C-20）。
type Rule struct {
	ID         string  `json:"id"`
	NodeID     string  `json:"node_id"`
	Name       string  `json:"name"`
	Remark     string  `json:"remark"`
	Enabled    bool    `json:"enabled"`
	Protocol   string  `json:"protocol"`
	ListenAddr string  `json:"listen_addr"`
	ListenPort int     `json:"listen_port"`
	TargetHost string  `json:"target_host"`
	TargetPort int     `json:"target_port"`
	Backend    string  `json:"backend"`
	Obfs       ObfsRef `json:"obfs"`
	Created    int64   `json:"created"`
	Updated    int64   `json:"updated"`
}

// Hop 链中的一个节点。Obfs 作用于该节点发出的出站方向（本节点 → 下一跳 / 目标）。
type Hop struct {
	NodeID     string  `json:"node_id"`
	ListenPort int     `json:"listen_port"` // 0 表示自动分配
	Backend    string  `json:"backend"`
	Obfs       ObfsRef `json:"obfs"`
}

// Chain 转发链（C-21）。
type Chain struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Remark     string `json:"remark"`
	Enabled    bool   `json:"enabled"`
	Protocol   string `json:"protocol"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	Hops       []Hop  `json:"hops"`
	Created    int64  `json:"created"`
	Updated    int64  `json:"updated"`
}

// Template 伪装参数模板（C-30 / C-31）。
type Template struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Type    string         `json:"type"`
	Params  api.FakeParams `json:"params"`
	Builtin bool           `json:"builtin"`
}

// AuditEntry 审计日志（C-44）。
type AuditEntry struct {
	ID     int64  `json:"id"`
	Time   int64  `json:"time"`
	User   string `json:"user"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// TrafficPoint 节点每分钟流量增量（C-53）。
type TrafficPoint struct {
	Time  int64  `json:"time"`
	Up    uint64 `json:"up"`
	Down  uint64 `json:"down"`
	Conns int    `json:"conns"`
}

// ChainRuleID 链中第 i 跳生成的规则 ID。
func ChainRuleID(chainID string, hop int) string {
	return chainID + "-h" + itoa(hop)
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
