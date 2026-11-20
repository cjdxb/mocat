package controller

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mocat/internal/api"
	"mocat/internal/tlsutil"
)

//go:embed web
var webFS embed.FS

// Server 控制端 HTTP 服务。
type Server struct {
	cfg    *Config
	store  *Store
	syncer *Syncer
	auth   *Auth
	log    *slog.Logger
	cert   tls.Certificate
	pin    string
}

// NewServer 创建服务。
func NewServer(cfg *Config, store *Store, syncer *Syncer, auth *Auth, cert tls.Certificate, log *slog.Logger) *Server {
	return &Server{cfg: cfg, store: store, syncer: syncer, auth: auth, cert: cert, pin: tlsutil.SPKIPin(cert), log: log}
}

type ctxKey int

const userKey ctxKey = 1

func userOf(r *http.Request) string {
	u, _ := r.Context().Value(userKey).(string)
	return u
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// Handler 路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// 无需登录
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /dl/install.sh", s.handleInstallScript)
	mux.HandleFunc("GET /dl/{file}", s.handleDownload)

	// 需要登录
	a := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireAuth(h)) }
	a("POST /api/logout", s.handleLogout)
	a("GET /api/me", s.handleMe)
	a("POST /api/password", s.handlePassword)
	a("GET /api/overview", s.handleOverview)

	a("GET /api/nodes", s.handleListNodes)
	a("POST /api/nodes", s.handleCreateNode)
	a("GET /api/nodes/{id}", s.handleGetNode)
	a("PUT /api/nodes/{id}", s.handleUpdateNode)
	a("DELETE /api/nodes/{id}", s.handleDeleteNode)
	a("POST /api/nodes/{id}/reset-token", s.handleResetToken)
	a("GET /api/nodes/{id}/install", s.handleInstallInfo)
	a("POST /api/nodes/{id}/trust-cert", s.handleTrustCert)
	a("POST /api/nodes/{id}/sync", s.handleSyncNode)
	a("GET /api/nodes/{id}/logs", s.handleNodeLogs)
	a("GET /api/nodes/{id}/traffic", s.handleNodeTraffic)

	a("GET /api/rules", s.handleListRules)
	a("POST /api/rules", s.handleSaveRule)
	a("PUT /api/rules/{id}", s.handleSaveRule)
	a("DELETE /api/rules/{id}", s.handleDeleteRule)

	a("GET /api/chains", s.handleListChains)
	a("POST /api/chains", s.handleSaveChain)
	a("PUT /api/chains/{id}", s.handleSaveChain)
	a("DELETE /api/chains/{id}", s.handleDeleteChain)

	a("GET /api/templates", s.handleListTemplates)
	a("POST /api/templates", s.handleSaveTemplate)
	a("PUT /api/templates/{id}", s.handleSaveTemplate)
	a("DELETE /api/templates/{id}", s.handleDeleteTemplate)

	a("GET /api/audit", s.handleAudit)

	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServer(http.FS(sub))
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/install.sh" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		static.ServeHTTP(w, r)
	}))
	return s.secureHeaders(mux)
}

func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		user, ok := s.auth.User(c.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "登录已过期")
			return
		}
		// CSRF 防护：修改类请求必须带自定义头（跨站请求无法在无 CORS 许可时设置）
		if r.Method != http.MethodGet && r.Header.Get("X-Mocat") != "1" {
			writeErr(w, http.StatusForbidden, "缺少请求头")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("请求格式错误: %v", err)
	}
	return nil
}

func (s *Server) audit(r *http.Request, action, detail string) {
	s.store.Audit(userOf(r), clientIP(r), action, detail)
	s.log.Info("操作审计", "user", userOf(r), "ip", clientIP(r), "action", action, "detail", detail)
}

// ---- 登录 ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.auth.Locked(ip) {
		writeErr(w, http.StatusTooManyRequests, "登录失败次数过多，请 10 分钟后再试")
		return
	}
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, ok := s.auth.Login(in.Username, in.Password, ip)
	if !ok {
		s.store.Audit(in.Username, ip, "登录失败", "")
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	s.store.Audit(in.Username, ip, "登录", "")
	writeJSON(w, http.StatusOK, map[string]string{"user": in.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"user": userOf(r)})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(in.New) < 8 {
		writeErr(w, http.StatusBadRequest, "新密码至少 8 个字符")
		return
	}
	c, _ := r.Cookie(sessionCookie)
	if !s.auth.ChangePassword(userOf(r), in.Old, in.New, c.Value) {
		writeErr(w, http.StatusBadRequest, "原密码错误")
		return
	}
	s.audit(r, "修改密码", "")
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// ---- 节点 ----

// NodeView 返回给前端的节点信息（不含 Token）。
type NodeView struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Remark        string      `json:"remark"`
	Host          string      `json:"host"`
	Port          int         `json:"port"`
	DataHost      string      `json:"data_host"`
	CertFP        string      `json:"cert_fp"`
	ConfigVersion int64       `json:"config_version"`
	Synced        bool        `json:"synced"`
	Runtime       NodeRuntime `json:"runtime"`
	RuleCount     int         `json:"rule_count"`
	FailedRules   int         `json:"failed_rules"`
	UpBytes       uint64      `json:"up_bytes"`
	DownBytes     uint64      `json:"down_bytes"`
	RateUp        float64     `json:"rate_up"`
	RateDown      float64     `json:"rate_down"`
	Conns         int         `json:"conns"`
}

func (s *Server) nodeView(n Node, compiled []CompiledRule) NodeView {
	rt := s.syncer.Runtime(n.ID)
	v := NodeView{ID: n.ID, Name: n.Name, Remark: n.Remark, Host: n.Host, Port: n.Port, DataHost: n.DataHost,
		CertFP: n.CertFP, ConfigVersion: n.ConfigVersion, Runtime: rt}
	v.Synced = rt.Status != nil && rt.Status.ConfigVersion == n.ConfigVersion
	v.RuleCount = len(compiled)
	for _, r := range compiled {
		st, _ := s.ruleState(n, rt, r.ID, r.Enabled)
		if st != api.StateRunning && st != api.StateDisabled {
			v.FailedRules++
		}
	}
	for _, x := range rt.Stats {
		v.UpBytes += x.UpBytes
		v.DownBytes += x.DownBytes
		v.Conns += x.Conns
	}
	for _, x := range rt.Rates {
		v.RateUp += x.Up
		v.RateDown += x.Down
	}
	// 详情之外不返回大块数据
	v.Runtime.Stats, v.Runtime.Rates = nil, nil
	return v
}

// ruleState 计算规则在 Web 上显示的状态。
func (s *Server) ruleState(n Node, rt NodeRuntime, ruleID string, enabled bool) (string, string) {
	if !enabled {
		return api.StateDisabled, ""
	}
	if !rt.Online {
		reason := "节点离线"
		if rt.LastError != "" {
			reason += "：" + rt.LastError
		}
		return "offline", reason
	}
	if rt.Status == nil || rt.Status.ConfigVersion != n.ConfigVersion {
		reason := "等待同步到节点"
		if rt.SyncError != "" {
			reason = rt.SyncError
		}
		return "syncing", reason
	}
	for _, st := range rt.Status.Rules {
		if st.ID == ruleID {
			return st.State, st.Reason
		}
	}
	return api.StatePending, ""
}

func (s *Server) compiled() (*World, map[string][]CompiledRule, error) {
	w, err := s.store.LoadWorld()
	if err != nil {
		return nil, nil, err
	}
	c, err := w.Compile()
	return w, c, err
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	world, compiled, err := s.compiled()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodes, _ := s.store.Nodes()
	out := []NodeView{}
	for _, n := range nodes {
		_ = world
		out = append(out, s.nodeView(n, compiled[n.ID]))
	}
	writeJSON(w, http.StatusOK, out)
}

type nodeInput struct {
	Name     string `json:"name"`
	Remark   string `json:"remark"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	DataHost string `json:"data_host"`
}

func (in *nodeInput) validate() error {
	in.Name, in.Host, in.DataHost = strings.TrimSpace(in.Name), strings.TrimSpace(in.Host), strings.TrimSpace(in.DataHost)
	if in.Name == "" || len(in.Name) > 64 {
		return errors.New("名称不能为空且不超过 64 个字符")
	}
	if !api.IsValidHost(in.Host) {
		return errors.New("管理地址格式不正确（IP 或域名）")
	}
	if in.Port == 0 {
		in.Port = 9443
	}
	if in.Port < 1 || in.Port > 65535 {
		return errors.New("管理端口必须在 1-65535 之间")
	}
	if in.DataHost != "" && !api.IsValidHost(in.DataHost) {
		return errors.New("数据面地址格式不正确")
	}
	return nil
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var in nodeInput
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	token := RandToken(24)
	n := Node{ID: RandToken(6), Name: in.Name, Remark: in.Remark, Host: in.Host, Port: in.Port, DataHost: in.DataHost,
		TokenEnc: s.store.Encrypt(token), Created: time.Now().Unix()}
	if err := s.store.PutNode(n); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "新建节点", fmt.Sprintf("%s (%s:%d)", n.Name, n.Host, n.Port))
	writeJSON(w, http.StatusOK, map[string]any{"node": s.nodeView(n, nil), "install": s.installInfo(r, n, token)})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.Node(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	_, compiled, err := s.compiled()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	v := s.nodeView(n, compiled[n.ID])
	writeJSON(w, http.StatusOK, map[string]any{"node": v, "rules": s.ruleViews(n, compiled[n.ID])})
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	var in nodeInput
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := r.PathValue("id")
	world, err := s.store.LoadWorld()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cur, ok := world.Nodes[id]
	if !ok {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	cur.Port, cur.DataHost = in.Port, in.DataHost
	world.Nodes[id] = cur
	if _, err := world.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.syncer.UpdateNode(id, func(n *Node) error {
		n.Name, n.Remark, n.Host, n.Port, n.DataHost = in.Name, in.Remark, in.Host, in.Port, in.DataHost
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.syncer.BumpVersions()
	s.syncer.Kick(id)
	s.audit(r, "修改节点", fmt.Sprintf("%s (%s:%d)", n.Name, n.Host, n.Port))
	writeJSON(w, http.StatusOK, s.nodeView(n, nil))
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.store.Node(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	chains, _ := s.store.Chains()
	for _, c := range chains {
		for _, h := range c.Hops {
			if h.NodeID == id {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("节点被转发链「%s」使用，请先修改或删除该链", c.Name))
				return
			}
		}
	}
	// 尽力通知节点清空规则，停止转发
	if cl, err := s.syncer.Client(n); err == nil && s.syncer.Runtime(id).Online {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		_ = cl.PutConfig(ctx, api.NodeConfig{Version: max(time.Now().UnixMilli(), n.ConfigVersion+1), Rules: []api.Rule{}})
		cancel()
	}
	if err := s.store.DeleteNode(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "删除节点", n.Name)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

// handleResetToken 重置节点凭据（C-13）：控制端立即改用新 Token；节点在线时同时推送给节点。
func (s *Server) handleResetToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.store.Node(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	token := RandToken(24)
	pushed := false
	if cl, err := s.syncer.Client(n); err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		pushed = cl.SetToken(ctx, token) == nil
		cancel()
	}
	n, err = s.syncer.UpdateNode(id, func(n *Node) error { n.TokenEnc = s.store.Encrypt(token); return nil })
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.syncer.Kick(id)
	s.audit(r, "重置节点凭据", fmt.Sprintf("%s，已推送到节点: %v", n.Name, pushed))
	writeJSON(w, http.StatusOK, map[string]any{"pushed": pushed, "install": s.installInfo(r, n, token)})
}

func (s *Server) handleInstallInfo(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.Node(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	tok, err := s.store.Decrypt(n.TokenEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "查看节点安装命令", n.Name)
	writeJSON(w, http.StatusOK, s.installInfo(r, n, tok))
}

func (s *Server) handleTrustCert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.syncer.UpdateNode(id, func(n *Node) error { n.CertFP = ""; return nil })
	if err != nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	s.syncer.Kick(id)
	s.audit(r, "信任节点新证书", n.Name)
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (s *Server) handleSyncNode(w http.ResponseWriter, r *http.Request) {
	s.syncer.Kick(r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func (s *Server) handleNodeLogs(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.Node(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	cl, err := s.syncer.Client(n)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	num, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if num <= 0 {
		num = 300
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	logs, err := cl.Logs(ctx, num)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "获取节点日志失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

func (s *Server) handleNodeTraffic(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > 24*7 {
		hours = 24
	}
	pts, err := s.store.Traffic(r.PathValue("id"), time.Now().Add(-time.Duration(hours)*time.Hour).Unix())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pts == nil {
		pts = []TrafficPoint{}
	}
	writeJSON(w, http.StatusOK, pts)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	l, err := s.store.AuditList(500)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if l == nil {
		l = []AuditEntry{}
	}
	writeJSON(w, http.StatusOK, l)
}

// ---- 安装（C-10） ----

func (s *Server) baseURL(r *http.Request) string {
	if s.cfg.PublicURL != "" {
		return strings.TrimRight(s.cfg.PublicURL, "/")
	}
	return "https://" + r.Host
}

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

func (s *Server) installInfo(r *http.Request, n Node, token string) map[string]any {
	base := s.baseURL(r)
	listen := "0.0.0.0:" + strconv.Itoa(n.Port)
	oneClick := fmt.Sprintf("curl -fsSL --insecure --pinnedpubkey %s %s/dl/install.sh | sudo bash -s -- --controller %s --pin %s --token %s --listen %s",
		shellQuote(s.pin), base, shellQuote(base), shellQuote(s.pin), token, listen)
	manual := fmt.Sprintf("sudo /opt/mocat/mocat-node init -token %s -listen %s && sudo systemctl enable --now mocat-node", token, listen)
	pkgs := []string{}
	for _, arch := range []string{"amd64", "arm64"} {
		if _, err := os.Stat(filepath.Join(s.cfg.DataDir, "packages", "mocat-node-linux-"+arch+".tar.gz")); err == nil {
			pkgs = append(pkgs, arch)
		}
	}
	return map[string]any{"token": token, "one_click": oneClick, "manual": manual, "packages": pkgs, "controller_pin": s.pin}
}

var pkgNameRe = regexp.MustCompile(`^mocat-node-linux-(amd64|arm64)\.tar\.gz$`)

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !pkgNameRe.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.cfg.DataDir, "packages", name))
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	b, err := webFS.ReadFile("web/install.sh")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(b)
}
