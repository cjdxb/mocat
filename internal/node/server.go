package node

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"mocat/internal/api"
	"mocat/internal/logx"
	"mocat/internal/version"
)

// Server 节点管理端口（HTTPS + Token 鉴权，A-01/A-03）。
type Server struct {
	cfg       *Config
	mgr       *Manager
	env       *Env
	ring      *logx.Ring
	log       *slog.Logger
	startedAt time.Time

	tokenMu sync.RWMutex
	token   string

	allow []*net.IPNet
	ban   *banList
}

// NewServer 创建管理 API 服务。
func NewServer(cfg *Config, mgr *Manager, env *Env, ring *logx.Ring, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, mgr: mgr, env: env, ring: ring, log: log, startedAt: time.Now(), token: cfg.Token, ban: newBanList()}
	for _, a := range cfg.AllowIPs {
		if !strings.Contains(a, "/") {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				a += "/32"
			} else {
				a += "/128"
			}
		}
		_, n, err := net.ParseCIDR(a)
		if err != nil {
			return nil, err
		}
		s.allow = append(s.allow, n)
	}
	return s, nil
}

// Handler 返回 HTTP 处理器。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/stats", s.handleStats)
	mux.HandleFunc("GET /api/v1/config", s.handleGetConfig)
	mux.HandleFunc("PUT /api/v1/config", s.handlePutConfig)
	mux.HandleFunc("GET /api/v1/logs", s.handleLogs)
	mux.HandleFunc("POST /api/v1/token", s.handleToken)
	return s.guard(mux)
}

// ListenAndServe 启动 HTTPS 服务。
func (s *Server) ListenAndServe(cert tls.Certificate) (*http.Server, error) {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("管理端口服务退出", "err", err)
		}
	}()
	s.log.Info("管理端口已监听", "addr", s.cfg.Listen)
	return srv, nil
}

func remoteIP(r *http.Request) net.IP {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	return net.ParseIP(h)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		if len(s.allow) > 0 {
			ok := false
			for _, n := range s.allow {
				if ip != nil && n.Contains(ip) {
					ok = true
					break
				}
			}
			if !ok {
				writeErr(w, http.StatusForbidden, "来源 IP 不在白名单中")
				return
			}
		}
		key := ip.String()
		if s.ban.banned(key) {
			writeErr(w, http.StatusTooManyRequests, "鉴权失败次数过多，请稍后再试")
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.tokenMu.RLock()
		want := s.token
		s.tokenMu.RUnlock()
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			if s.ban.fail(key) {
				s.log.Warn("管理端口鉴权失败次数过多，临时封禁", "ip", key)
			} else {
				s.log.Warn("管理端口鉴权失败", "ip", key, "path", r.URL.Path)
			}
			writeErr(w, http.StatusUnauthorized, "鉴权失败")
			return
		}
		s.ban.reset(key)
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, api.ErrorResponse{Error: msg})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := api.NodeStatus{
		Version:       version.Version,
		System:        SysInfo(),
		Backends:      s.env.Backends,
		ConfigVersion: s.mgr.Current().Version,
		Rules:         s.mgr.Status(),
		StartedAt:     s.startedAt.Unix(),
		Warnings:      s.env.Warnings,
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, api.NodeStats{Time: time.Now().UnixMilli(), Rules: s.mgr.Stats()})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Current())
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var c api.NodeConfig
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeErr(w, http.StatusBadRequest, "配置格式错误: "+err.Error())
		return
	}
	if err := s.mgr.Apply(c, false); err != nil {
		if errors.Is(err, ErrStaleConfig) {
			writeJSON(w, http.StatusConflict, api.ErrorResponse{Error: err.Error(), CurrentVersion: s.mgr.Current().Version})
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": c.Version, "rules": s.mgr.Status()})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 1000 {
		n = 200
	}
	writeJSON(w, http.StatusOK, s.ring.Last(n))
}

// handleToken 更换节点凭据（C-13）。新 token 写入配置文件后立即生效，旧 token 立即失效。
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var t api.TokenUpdate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil || len(t.Token) < 16 {
		writeErr(w, http.StatusBadRequest, "token 不合法（至少 16 个字符）")
		return
	}
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	s.cfg.Token = t.Token
	if err := s.cfg.Save(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	s.token = t.Token
	s.log.Info("节点凭据已更新")
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// banList 连续鉴权失败限速（A-07）：10 分钟内失败 10 次封禁 15 分钟。
type banList struct {
	mu sync.Mutex
	m  map[string]*banEntry
}

type banEntry struct {
	fails int
	first time.Time
	until time.Time
}

func newBanList() *banList { return &banList{m: map[string]*banEntry{}} }

func (b *banList) banned(k string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[k]
	return e != nil && time.Now().Before(e.until)
}

func (b *banList) fail(k string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if len(b.m) > 10000 {
		for key, e := range b.m {
			if now.Sub(e.first) > 10*time.Minute && now.After(e.until) {
				delete(b.m, key)
			}
		}
	}
	e := b.m[k]
	if e == nil || now.Sub(e.first) > 10*time.Minute {
		e = &banEntry{first: now}
		b.m[k] = e
	}
	e.fails++
	if e.fails >= 10 {
		e.until = now.Add(15 * time.Minute)
		e.fails = 0
		e.first = now
		return true
	}
	return false
}

func (b *banList) reset(k string) {
	b.mu.Lock()
	delete(b.m, k)
	b.mu.Unlock()
}
