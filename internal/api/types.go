// Package api 定义控制端与节点之间控制通道使用的数据结构。
package api

import "encoding/json"

// 协议
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// 转发后端
const (
	BackendSocat = "socat"
	BackendNft   = "nft"
)

// 伪装类型（插件名）。以后新增“真实握手”等类型时只需增加常量和插件实现。
const (
	ObfsNone     = "none"
	ObfsFakeHTTP = "fakehttp"
	ObfsFakeSIP  = "fakesip"
)

// Obfs 伪装配置，按“类型 + 参数”组织，参数由对应插件自行解析。
type Obfs struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

// FakeParams 是 fakehttp / fakesip 共用的参数结构。
type FakeParams struct {
	Host       string `json:"host,omitempty"`        // FakeHTTP -h
	URI        string `json:"uri,omitempty"`         // FakeSIP -u
	TTL        int    `json:"ttl,omitempty"`         // -t
	Repeat     int    `json:"repeat,omitempty"`      // -r
	PayloadB64 string `json:"payload_b64,omitempty"` // -b 自定义载荷（base64）
}

// Rule 一条转发规则（节点只理解单条规则，链由控制端编排）。
type Rule struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Enabled    bool   `json:"enabled"`
	Protocol   string `json:"protocol"`
	ListenAddr string `json:"listen_addr,omitempty"` // 为空表示所有地址（IPv4）
	ListenPort int    `json:"listen_port"`
	TargetHost string `json:"target_host"` // IPv4 / IPv6 / 域名
	TargetPort int    `json:"target_port"`
	Backend    string `json:"backend"`
	Obfs       Obfs   `json:"obfs"`
}

// NodeConfig 控制端下发给节点的完整配置。
type NodeConfig struct {
	Version int64  `json:"version"`
	Rules   []Rule `json:"rules"`
}

// 规则运行状态
const (
	StateRunning  = "running"
	StateFailed   = "failed"
	StateDisabled = "disabled"
	StatePending  = "pending"
)

// RuleStatus 规则运行状态。
type RuleStatus struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	ResolvedIP string `json:"resolved_ip,omitempty"`
}

// BackendInfo 后端 / 依赖可用性。
type BackendInfo struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Note      string `json:"note,omitempty"`
}

// SystemInfo 节点系统信息。
type SystemInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	Distro   string `json:"distro,omitempty"`
}

// NodeStatus 节点状态（GET /api/v1/status）。
type NodeStatus struct {
	Version       string        `json:"version"`
	System        SystemInfo    `json:"system"`
	Backends      []BackendInfo `json:"backends"`
	ConfigVersion int64         `json:"config_version"`
	Rules         []RuleStatus  `json:"rules"`
	StartedAt     int64         `json:"started_at"`
	Warnings      []string      `json:"warnings,omitempty"`
}

// RuleStats 规则流量统计。Up = 本节点发往目标方向，Down = 目标返回方向。
type RuleStats struct {
	ID          string `json:"id"`
	UpBytes     uint64 `json:"up_bytes"`
	DownBytes   uint64 `json:"down_bytes"`
	UpPackets   uint64 `json:"up_packets"`
	DownPackets uint64 `json:"down_packets"`
	Conns       int    `json:"conns"`
	Blocked     uint64 `json:"blocked"` // 伪装队列丢弃计数（N-2B）
}

// NodeStats GET /api/v1/stats。
type NodeStats struct {
	Time  int64       `json:"time"` // unix 毫秒
	Rules []RuleStats `json:"rules"`
}

// LogEntry 日志行。
type LogEntry struct {
	Time  int64  `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// TokenUpdate POST /api/v1/token。
type TokenUpdate struct {
	Token string `json:"token"`
}

// ErrorResponse 错误响应体。
type ErrorResponse struct {
	Error          string `json:"error"`
	CurrentVersion int64  `json:"current_version,omitempty"`
}
