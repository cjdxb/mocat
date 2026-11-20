package controller

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"mocat/internal/api"
	"mocat/internal/tlsutil"
)

func TestCompileChain(t *testing.T) {
	w := &World{
		Nodes: map[string]Node{
			"a": {ID: "a", Name: "A", Host: "10.0.0.1", Port: 9443},
			"b": {ID: "b", Name: "B", Host: "10.0.0.2", DataHost: "198.51.100.2", Port: 9443},
			"c": {ID: "c", Name: "C", Host: "10.0.0.3", Port: 9443},
		},
		Templates: map[string]Template{BuiltinHTTPTemplate: {ID: BuiltinHTTPTemplate, Type: api.ObfsFakeHTTP, Params: api.DefaultFakeParams(api.ObfsFakeHTTP)}},
		Chains: []Chain{{ID: "c1", Name: "链", Enabled: true, Protocol: "tcp", TargetHost: "example.com", TargetPort: 443, Hops: []Hop{
			{NodeID: "a", ListenPort: 1000, Backend: "socat", Obfs: ObfsRef{Type: api.ObfsFakeHTTP, TemplateID: BuiltinHTTPTemplate}},
			{NodeID: "b", ListenPort: 2000, Backend: "nft", Obfs: ObfsRef{Type: api.ObfsNone}},
			{NodeID: "c", ListenPort: 3000, Backend: "socat", Obfs: ObfsRef{Type: api.ObfsFakeHTTP, Params: json.RawMessage(`{"host":"x.com"}`)}},
		}}},
	}
	out, err := w.Validate()
	if err != nil {
		t.Fatal(err)
	}
	ra, rb, rc := out["a"][0], out["b"][0], out["c"][0]
	// A 的目标 = B 的数据面地址 + B 的入口端口
	if ra.TargetHost != "198.51.100.2" || ra.TargetPort != 2000 {
		t.Errorf("A 目标错误: %s:%d", ra.TargetHost, ra.TargetPort)
	}
	if rb.TargetHost != "10.0.0.3" || rb.TargetPort != 3000 {
		t.Errorf("B 目标错误: %s:%d", rb.TargetHost, rb.TargetPort)
	}
	if rc.TargetHost != "example.com" || rc.TargetPort != 443 {
		t.Errorf("C 目标错误: %s:%d", rc.TargetHost, rc.TargetPort)
	}
	if ra.Obfs.Type != api.ObfsFakeHTTP || !strings.Contains(string(ra.Obfs.Params), "speedtest") {
		t.Errorf("模板未展开: %s", ra.Obfs.Params)
	}
	if ra.ID != "c1-h0" || rc.ID != "c1-h2" {
		t.Errorf("规则 ID: %s %s", ra.ID, rc.ID)
	}

	// UDP 链不能选 FakeHTTP（C-23）
	w.Chains[0].Protocol = "udp"
	if _, err := w.Validate(); err == nil || !strings.Contains(err.Error(), "FakeHTTP 只能用于 TCP") {
		t.Errorf("期望协议/伪装不匹配错误，得到 %v", err)
	}
	// 端口冲突：同节点同协议同端口
	w.Chains[0].Protocol = "tcp"
	w.Rules = []Rule{{ID: "r1", NodeID: "a", Name: "冲突", Enabled: true, Protocol: "tcp", ListenPort: 1000, TargetHost: "1.1.1.1", TargetPort: 1, Backend: "socat"}}
	if _, err := w.Validate(); err == nil || !strings.Contains(err.Error(), "冲突") {
		t.Errorf("期望端口冲突，得到 %v", err)
	}
}

// ---- HTTP API ----

type testEnv struct {
	t   *testing.T
	srv *httptest.Server
	cl  *http.Client
	pw  string
}

func newTestEnv(t *testing.T) *testEnv {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	auth := NewAuth(store)
	pw, err := auth.EnsureAdmin()
	if err != nil || pw == "" {
		t.Fatalf("创建管理员失败: %v", err)
	}
	cert, err := tlsutil.LoadOrCreate(filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key"), "test", []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := NewSyncer(store, log)
	s := NewServer(&Config{DataDir: dir}, store, syncer, auth, cert, log)
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	cl := ts.Client()
	cl.Jar = jar
	cl.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &testEnv{t: t, srv: ts, cl: cl, pw: pw}
}

func (e *testEnv) do(method, path string, body any, csrf bool) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if csrf {
		req.Header.Set("X-Mocat", "1")
	}
	resp, err := e.cl.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return resp.StatusCode, m
}

func TestAPIFlow(t *testing.T) {
	e := newTestEnv(t)
	if code, _ := e.do("GET", "/api/overview", nil, false); code != 401 {
		t.Fatalf("未登录应返回 401，得到 %d", code)
	}
	if code, _ := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}, false); code != 401 {
		t.Fatalf("错误密码应 401，得到 %d", code)
	}
	if code, m := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": e.pw}, false); code != 200 {
		t.Fatalf("登录失败 %d %v", code, m)
	}
	// 缺少 CSRF 头的修改请求被拒绝
	if code, _ := e.do("POST", "/api/nodes", map[string]any{"name": "n1", "host": "127.0.0.1", "port": 9443}, false); code != 403 {
		t.Fatalf("缺少 X-Mocat 头应 403，得到 %d", code)
	}
	code, m := e.do("POST", "/api/nodes", map[string]any{"name": "n1", "host": "127.0.0.1", "port": 9443}, true)
	if code != 200 {
		t.Fatalf("新建节点失败 %d %v", code, m)
	}
	inst := m["install"].(map[string]any)
	tok := inst["token"].(string)
	if len(tok) < 32 || !strings.Contains(inst["one_click"].(string), tok) || !strings.Contains(inst["one_click"].(string), "--pinnedpubkey") {
		t.Fatalf("安装命令不正确: %v", inst)
	}
	nodeID := m["node"].(map[string]any)["id"].(string)

	rule := map[string]any{"node_id": nodeID, "name": "web", "enabled": true, "protocol": "tcp", "listen_port": 8080,
		"target_host": "example.com", "target_port": 80, "backend": "socat", "obfs": map[string]any{"type": "fakehttp", "template_id": BuiltinHTTPTemplate}}
	if code, m := e.do("POST", "/api/rules", rule, true); code != 200 {
		t.Fatalf("新建规则失败 %d %v", code, m)
	}
	// 端口冲突
	if code, m := e.do("POST", "/api/rules", rule, true); code != 400 || !strings.Contains(m["error"].(string), "冲突") {
		t.Fatalf("期望端口冲突 400，得到 %d %v", code, m)
	}
	// 与管理端口冲突
	rule["listen_port"] = 9443
	if code, _ := e.do("POST", "/api/rules", rule, true); code != 400 {
		t.Fatalf("期望与管理端口冲突，得到 %d", code)
	}
	// UDP + FakeHTTP
	rule["listen_port"], rule["protocol"] = 8081, "udp"
	if code, _ := e.do("POST", "/api/rules", rule, true); code != 400 {
		t.Fatalf("期望 UDP+FakeHTTP 被拒绝，得到 %d", code)
	}

	// 链：端口自动分配
	chain := map[string]any{"name": "ch", "enabled": true, "protocol": "tcp", "target_host": "1.1.1.1", "target_port": 443,
		"hops": []map[string]any{{"node_id": nodeID, "listen_port": 0, "backend": "nft", "obfs": map[string]any{"type": "none"}}}}
	code, m = e.do("POST", "/api/chains", chain, true)
	if code != 200 {
		t.Fatalf("新建链失败 %d %v", code, m)
	}
	hops := m["hops"].([]any)
	if p := hops[0].(map[string]any)["listen_port"].(float64); p < 20000 || p >= 30000 {
		t.Fatalf("自动分配端口错误: %v", p)
	}

	// 节点被链使用时不能删除
	if code, _ := e.do("DELETE", "/api/nodes/"+nodeID, nil, true); code != 400 {
		t.Fatalf("被链引用的节点不应允许删除，得到 %d", code)
	}
	if code, m := e.do("GET", "/api/overview", nil, false); code != 200 || m["rules"].(float64) != 2 {
		t.Fatalf("总览错误 %d %v", code, m)
	}
	if code, _ := e.do("GET", "/api/audit", nil, false); code != 200 {
		t.Fatal("审计日志读取失败")
	}
}

func TestLoginLockout(t *testing.T) {
	e := newTestEnv(t)
	for i := 0; i < 5; i++ {
		e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "x"}, false)
	}
	if code, _ := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": e.pw}, false); code != 429 {
		t.Fatalf("连续失败后应锁定，得到 %d", code)
	}
}

func TestTokenEncryption(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	enc := s.Encrypt("secret-token")
	if strings.Contains(enc, "secret") {
		t.Fatal("未加密")
	}
	if dec, err := s.Decrypt(enc); err != nil || dec != "secret-token" {
		t.Fatalf("解密失败 %v %q", err, dec)
	}
}
