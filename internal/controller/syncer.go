package controller

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"mocat/internal/api"
)

// Rate 实时速率（字节/秒）。
type Rate struct {
	Up   float64 `json:"up"`
	Down float64 `json:"down"`
}

// NodeRuntime 控制端内存中的节点运行时信息。
type NodeRuntime struct {
	Online    bool                     `json:"online"`
	LastSeen  int64                    `json:"last_seen"`
	LastError string                   `json:"last_error,omitempty"`
	SyncError string                   `json:"sync_error,omitempty"`
	FPAlert   string                   `json:"fp_alert,omitempty"` // 证书指纹变化时的新指纹
	Status    *api.NodeStatus          `json:"status,omitempty"`
	Stats     map[string]api.RuleStats `json:"stats,omitempty"`
	Rates     map[string]Rate          `json:"rates,omitempty"`
	StatsTime int64                    `json:"stats_time"`

	minuteStart int64
	minuteUp    uint64
	minuteDown  uint64
}

// Syncer 定期探测节点、下发配置、采集流量（C-24、C-51、C-53）。
type Syncer struct {
	store *Store
	log   *slog.Logger

	mu      sync.RWMutex
	rt      map[string]*NodeRuntime
	kick    map[string]chan struct{}
	cancels map[string]context.CancelFunc
	cfgMu   sync.Mutex // 串行化配置版本提升
}

// Interval 轮询间隔。
const Interval = 10 * time.Second

// NewSyncer 创建同步器。
func NewSyncer(store *Store, log *slog.Logger) *Syncer {
	return &Syncer{store: store, log: log, rt: map[string]*NodeRuntime{}, kick: map[string]chan struct{}{}, cancels: map[string]context.CancelFunc{}}
}

// Run 维护每个节点的同步协程。
func (s *Syncer) Run(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	s.refreshWorkers(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshWorkers(ctx)
		case <-prune.C:
			s.store.PruneTraffic(time.Now().AddDate(0, 0, -7).Unix())
		}
	}
}

func (s *Syncer) refreshWorkers(ctx context.Context) {
	nodes, err := s.store.Nodes()
	if err != nil {
		s.log.Error("读取节点失败", "err", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, n := range nodes {
		seen[n.ID] = true
		if _, ok := s.cancels[n.ID]; ok {
			continue
		}
		wctx, cancel := context.WithCancel(ctx)
		s.cancels[n.ID] = cancel
		s.kick[n.ID] = make(chan struct{}, 1)
		s.rt[n.ID] = &NodeRuntime{}
		go s.worker(wctx, n.ID, s.kick[n.ID])
	}
	for id, cancel := range s.cancels {
		if !seen[id] {
			cancel()
			delete(s.cancels, id)
			delete(s.kick, id)
			delete(s.rt, id)
		}
	}
}

// Kick 立即同步指定节点（规则变更后调用）。
func (s *Syncer) Kick(nodeID string) {
	s.mu.RLock()
	ch := s.kick[nodeID]
	s.mu.RUnlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Runtime 返回节点运行时信息副本。
func (s *Syncer) Runtime(nodeID string) NodeRuntime {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r := s.rt[nodeID]; r != nil {
		return *r
	}
	return NodeRuntime{}
}

func (s *Syncer) update(nodeID string, f func(r *NodeRuntime)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.rt[nodeID]; r != nil {
		f(r)
	}
}

func (s *Syncer) worker(ctx context.Context, nodeID string, kick chan struct{}) {
	for {
		s.syncOnce(ctx, nodeID)
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-time.After(Interval):
		}
	}
}

// Client 构造访问节点的客户端。
func (s *Syncer) Client(n Node) (*NodeClient, error) {
	tok, err := s.store.Decrypt(n.TokenEnc)
	if err != nil {
		return nil, err
	}
	return NewNodeClient(n, tok), nil
}

// UpdateNode 在锁内读取-修改-写回节点，避免与同步协程互相覆盖。
func (s *Syncer) UpdateNode(id string, f func(n *Node) error) (Node, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	n, err := s.store.Node(id)
	if err != nil {
		return n, err
	}
	if err := f(&n); err != nil {
		return n, err
	}
	return n, s.store.PutNode(n)
}

// BumpVersions 在任意配置变更后调用：内容变化的节点提升配置版本并立即同步（A-06）。
func (s *Syncer) BumpVersions() error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	w, err := s.store.LoadWorld()
	if err != nil {
		return err
	}
	compiled, err := w.Compile()
	if err != nil {
		return err
	}
	for id, n := range w.Nodes {
		h := NodeConfigHash(compiled[id])
		if h == n.ConfigHash {
			continue
		}
		v := time.Now().UnixMilli()
		if v <= n.ConfigVersion {
			v = n.ConfigVersion + 1
		}
		n.ConfigVersion, n.ConfigHash = v, h
		if err := s.store.PutNode(n); err != nil {
			return err
		}
		s.Kick(id)
	}
	return nil
}

func (s *Syncer) syncOnce(ctx context.Context, nodeID string) {
	n, err := s.store.Node(nodeID)
	if err != nil {
		return
	}
	cl, err := s.Client(n)
	if err != nil {
		s.update(nodeID, func(r *NodeRuntime) { r.Online, r.LastError = false, "Token 解密失败: "+err.Error() })
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	st, err := cl.Status(cctx)
	if err != nil {
		msg := err.Error()
		var he *HTTPError
		if errors.As(err, &he) && he.Code == http.StatusUnauthorized {
			msg = "鉴权失败：节点 Token 不匹配"
		}
		s.update(nodeID, func(r *NodeRuntime) {
			r.Online, r.LastError = false, msg
			if errors.Is(err, ErrFingerprintMismatch) {
				r.FPAlert = cl.Mismatch()
			}
		})
		return
	}
	// 首次连接时记录证书指纹（TOFU）
	if n.CertFP == "" && cl.SeenFingerprint() != "" {
		s.cfgMu.Lock()
		if cur, err := s.store.Node(nodeID); err == nil && cur.CertFP == "" {
			cur.CertFP = cl.SeenFingerprint()
			_ = s.store.PutNode(cur)
			s.log.Info("已记录节点证书指纹", "node", n.Name, "fp", cur.CertFP)
		}
		s.cfgMu.Unlock()
	}
	now := time.Now()
	s.update(nodeID, func(r *NodeRuntime) {
		r.Online, r.LastSeen, r.LastError, r.FPAlert, r.Status = true, now.Unix(), "", "", st
	})

	// 下发配置
	if st.ConfigVersion != n.ConfigVersion {
		syncErr := s.push(cctx, cl, n, st.ConfigVersion)
		s.update(nodeID, func(r *NodeRuntime) { r.SyncError = syncErr })
		if syncErr == "" {
			if st2, err := cl.Status(cctx); err == nil {
				s.update(nodeID, func(r *NodeRuntime) { r.Status = st2 })
			}
		}
	} else {
		s.update(nodeID, func(r *NodeRuntime) { r.SyncError = "" })
	}

	// 流量统计
	stats, err := cl.Stats(cctx)
	if err == nil {
		s.recordStats(nodeID, stats)
	}
}

func (s *Syncer) push(ctx context.Context, cl *NodeClient, n Node, nodeVersion int64) string {
	w, err := s.store.LoadWorld()
	if err != nil {
		return err.Error()
	}
	compiled, err := w.Compile()
	if err != nil {
		return err.Error()
	}
	cfg := api.NodeConfig{Version: n.ConfigVersion, Rules: []api.Rule{}}
	for _, r := range compiled[n.ID] {
		cfg.Rules = append(cfg.Rules, r.Rule)
	}
	if nodeVersion > n.ConfigVersion {
		// 节点上的版本比控制端新（例如控制端数据恢复过），控制端为准：提升版本后再下发。
		s.cfgMu.Lock()
		cur, err := s.store.Node(n.ID)
		if err == nil {
			cur.ConfigVersion = nodeVersion + 1
			_ = s.store.PutNode(cur)
			cfg.Version = cur.ConfigVersion
		}
		s.cfgMu.Unlock()
	}
	if err := cl.PutConfig(ctx, cfg); err != nil {
		s.log.Warn("下发配置失败", "node", n.Name, "err", err)
		return "下发配置失败: " + err.Error()
	}
	s.log.Info("已下发配置", "node", n.Name, "version", cfg.Version, "rules", len(cfg.Rules))
	return ""
}

func (s *Syncer) recordStats(nodeID string, st *api.NodeStats) {
	var point *TrafficPoint
	s.update(nodeID, func(r *NodeRuntime) {
		cur := map[string]api.RuleStats{}
		for _, x := range st.Rules {
			cur[x.ID] = x
		}
		rates := map[string]Rate{}
		var dUp, dDown uint64
		conns := 0
		if r.Stats != nil && st.Time > r.StatsTime {
			dt := float64(st.Time-r.StatsTime) / 1000
			for id, x := range cur {
				conns += x.Conns
				p, ok := r.Stats[id]
				if !ok || x.UpBytes < p.UpBytes || x.DownBytes < p.DownBytes {
					continue // 计数器被重置（节点重启等）
				}
				du, dd := x.UpBytes-p.UpBytes, x.DownBytes-p.DownBytes
				dUp += du
				dDown += dd
				rates[id] = Rate{Up: float64(du) / dt, Down: float64(dd) / dt}
			}
		}
		r.Stats, r.Rates, r.StatsTime = cur, rates, st.Time
		// 按分钟累计，写入历史（C-53）
		minute := st.Time / 60000 * 60
		if r.minuteStart == 0 {
			r.minuteStart = minute
		}
		r.minuteUp += dUp
		r.minuteDown += dDown
		if minute > r.minuteStart {
			point = &TrafficPoint{Time: r.minuteStart, Up: r.minuteUp, Down: r.minuteDown, Conns: conns}
			r.minuteStart, r.minuteUp, r.minuteDown = minute, 0, 0
		}
	})
	if point != nil {
		if err := s.store.AddTraffic(nodeID, *point); err != nil {
			s.log.Warn("保存流量历史失败", "err", err)
		}
	}
}
