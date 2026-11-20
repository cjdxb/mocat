// Package obfs 定义伪装插件接口（N-53）。
//
// 一个插件描述：哪些规则可以共用一个伪装进程（GroupKey）、如何启动该进程（Command）、
// 以及需要在 mocat 的 nftables 表中加入哪些规则把对应报文送入队列（Rules）。
// 以后新增“真实握手”等类型时，实现本接口并在 Registry 中注册即可，转发和管理逻辑无需改动。
package obfs

import (
	"fmt"

	"mocat/internal/api"
)

// GroupEnv 一个伪装进程分到的资源。
type GroupEnv struct {
	Queue    int    // NFQUEUE 队列号
	Mark     uint32 // 伪装进程自己发出报文的 fwmark
	Mask     uint32 // fwmark 掩码
	StateDir string // 可写目录（存放自定义载荷等）
	Index    int
}

// RuleEnv 单条规则在 nftables 中的匹配信息。
type RuleEnv struct {
	CtMark     uint32 // 该规则连接的 ct mark
	Mask       uint32
	Backend    string
	Protocol   string
	ListenPort int
	ListenAddr string
	HasFib     bool
}

// Rules 插件需要加入的 nft 规则行，按链分组。
type Rules struct {
	Raw  []string // output raw，priority -300（伪装进程自发报文，在 notrack 之前）
	Pre  []string // prerouting filter，priority -150（在 DNAT 之前，看到线上地址）
	Post []string // postrouting filter，priority 110（在 SNAT 之后，看到线上地址）
}

// Plugin 伪装插件。
type Plugin interface {
	Name() string
	Protocol() string
	// Binary 返回依赖的可执行文件路径，空表示不可用。
	Binary() string
	// GroupKey 规范化参数后返回分组键，参数相同的规则共用进程（N-54）。
	GroupKey(o api.Obfs) (string, error)
	// Command 返回进程参数。
	Command(o api.Obfs, g GroupEnv) ([]string, error)
	// Rules 返回该规则需要的 nft 规则。
	Rules(r RuleEnv, g GroupEnv) Rules
	// GroupRules 返回该伪装进程（与具体规则无关）需要的 nft 规则。
	GroupRules(o api.Obfs, g GroupEnv) Rules
}

// Registry 插件表。
type Registry map[string]Plugin

// Get 按类型取插件。
func (r Registry) Get(typ string) (Plugin, error) {
	p, ok := r[typ]
	if !ok {
		return nil, fmt.Errorf("不支持的伪装类型 %q", typ)
	}
	return p, nil
}
