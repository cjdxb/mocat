package controller

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"mocat/internal/api"
)

// Store 基于 SQLite 的存储（C-03）。节点 / 规则 / 链 / 模板以 JSON 文档形式保存。
type Store struct {
	db  *sql.DB
	mu  sync.Mutex // 串行化写操作
	gcm cipher.AEAD
}

const schema = `
CREATE TABLE IF NOT EXISTS docs(kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(kind, id));
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, pass_hash TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER, user TEXT, ip TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS traffic(node_id TEXT, time INTEGER, up INTEGER, down INTEGER, conns INTEGER);
CREATE INDEX IF NOT EXISTS traffic_idx ON traffic(node_id, time);
`

const (
	kindNode     = "node"
	kindRule     = "rule"
	kindChain    = "chain"
	kindTemplate = "template"
)

// OpenStore 打开数据库并初始化。
func OpenStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "mocat.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	key, err := loadSecret(filepath.Join(dataDir, "secret.key"))
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(blk)
	s := &Store{db: db, gcm: gcm}
	if err := s.ensureBuiltinTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

func loadSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		k, err := hex.DecodeString(string(b))
		if err == nil && len(k) == 32 {
			return k, nil
		}
		return nil, fmt.Errorf("密钥文件 %s 损坏", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, []byte(hex.EncodeToString(k)), 0o600)
}

// Encrypt 加密敏感字段（NF-06）。
func (s *Store) Encrypt(plain string) string {
	nonce := make([]byte, s.gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(s.gcm.Seal(nonce, nonce, []byte(plain), nil))
}

// Decrypt 解密。
func (s *Store) Decrypt(enc string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b) < s.gcm.NonceSize() {
		return "", errors.New("密文格式错误")
	}
	p, err := s.gcm.Open(nil, b[:s.gcm.NonceSize()], b[s.gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(p), nil
}

// ---- 通用文档操作 ----

func (s *Store) put(kind, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO docs(kind,id,data) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data`, kind, id, string(b))
	return err
}

func (s *Store) get(kind, id string, v any) error {
	var data string
	err := s.db.QueryRow(`SELECT data FROM docs WHERE kind=? AND id=?`, kind, id).Scan(&data)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), v)
}

func (s *Store) del(kind, id string) error {
	_, err := s.db.Exec(`DELETE FROM docs WHERE kind=? AND id=?`, kind, id)
	return err
}

func listDocs[T any](s *Store, kind string) ([]T, error) {
	rows, err := s.db.Query(`SELECT data FROM docs WHERE kind=?`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- 节点 / 规则 / 链 / 模板 ----

func (s *Store) Nodes() ([]Node, error) {
	ns, err := listDocs[Node](s, kindNode)
	sort.Slice(ns, func(i, j int) bool { return ns[i].Created < ns[j].Created })
	return ns, err
}
func (s *Store) Node(id string) (Node, error) { var n Node; return n, s.get(kindNode, id, &n) }
func (s *Store) PutNode(n Node) error           { return s.put(kindNode, n.ID, n) }

func (s *Store) Rules() ([]Rule, error) {
	rs, err := listDocs[Rule](s, kindRule)
	sort.Slice(rs, func(i, j int) bool { return rs[i].Created < rs[j].Created })
	return rs, err
}
func (s *Store) Rule(id string) (Rule, error) { var r Rule; return r, s.get(kindRule, id, &r) }
func (s *Store) PutRule(r Rule) error           { return s.put(kindRule, r.ID, r) }
func (s *Store) DeleteRule(id string) error     { return s.del(kindRule, id) }

func (s *Store) Chains() ([]Chain, error) {
	cs, err := listDocs[Chain](s, kindChain)
	sort.Slice(cs, func(i, j int) bool { return cs[i].Created < cs[j].Created })
	return cs, err
}
func (s *Store) Chain(id string) (Chain, error) { var c Chain; return c, s.get(kindChain, id, &c) }
func (s *Store) PutChain(c Chain) error           { return s.put(kindChain, c.ID, c) }
func (s *Store) DeleteChain(id string) error      { return s.del(kindChain, id) }

func (s *Store) Templates() ([]Template, error) {
	ts, err := listDocs[Template](s, kindTemplate)
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].Builtin != ts[j].Builtin {
			return ts[i].Builtin
		}
		return ts[i].Name < ts[j].Name
	})
	return ts, err
}
func (s *Store) Template(id string) (Template, error) {
	var t Template
	return t, s.get(kindTemplate, id, &t)
}
func (s *Store) PutTemplate(t Template) error  { return s.put(kindTemplate, t.ID, t) }
func (s *Store) DeleteTemplate(id string) error { return s.del(kindTemplate, id) }

// DeleteNode 删除节点及其单节点规则（链需由调用方先检查）。
func (s *Store) DeleteNode(id string) error {
	rules, err := s.Rules() // 必须在事务外读取：连接池只有 1 个连接
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range rules {
		if r.NodeID == id {
			if _, err := tx.Exec(`DELETE FROM docs WHERE kind=? AND id=?`, kindRule, r.ID); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM docs WHERE kind=? AND id=?`, kindNode, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM traffic WHERE node_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// 内置模板 ID
const (
	BuiltinHTTPTemplate = "builtin-fakehttp"
	BuiltinSIPTemplate  = "builtin-fakesip"
)

func (s *Store) ensureBuiltinTemplates() error {
	for _, t := range []Template{
		{ID: BuiltinHTTPTemplate, Name: "默认 FakeHTTP", Type: api.ObfsFakeHTTP, Params: api.DefaultFakeParams(api.ObfsFakeHTTP), Builtin: true},
		{ID: BuiltinSIPTemplate, Name: "默认 FakeSIP", Type: api.ObfsFakeSIP, Params: api.DefaultFakeParams(api.ObfsFakeSIP), Builtin: true},
	} {
		if err := s.PutTemplate(t); err != nil {
			return err
		}
	}
	return nil
}

// ---- 用户 ----

func (s *Store) UserCount() (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
}

func (s *Store) UserHash(name string) (string, error) {
	var h string
	return h, s.db.QueryRow(`SELECT pass_hash FROM users WHERE username=?`, name).Scan(&h)
}

func (s *Store) SetUser(name, hash string) error {
	_, err := s.db.Exec(`INSERT INTO users(username,pass_hash,created) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET pass_hash=excluded.pass_hash`,
		name, hash, time.Now().Unix())
	return err
}

// ---- 审计 ----

func (s *Store) Audit(user, ip, action, detail string) {
	_, _ = s.db.Exec(`INSERT INTO audit(time,user,ip,action,detail) VALUES(?,?,?,?,?)`, time.Now().Unix(), user, ip, action, detail)
}

func (s *Store) AuditList(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id,time,user,ip,action,detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.User, &e.IP, &e.Action, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- 流量历史 ----

func (s *Store) AddTraffic(nodeID string, p TrafficPoint) error {
	_, err := s.db.Exec(`INSERT INTO traffic(node_id,time,up,down,conns) VALUES(?,?,?,?,?)`, nodeID, p.Time, p.Up, p.Down, p.Conns)
	return err
}

func (s *Store) Traffic(nodeID string, since int64) ([]TrafficPoint, error) {
	rows, err := s.db.Query(`SELECT time,up,down,conns FROM traffic WHERE node_id=? AND time>=? ORDER BY time`, nodeID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficPoint
	for rows.Next() {
		var p TrafficPoint
		if err := rows.Scan(&p.Time, &p.Up, &p.Down, &p.Conns); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PruneTraffic(before int64) {
	_, _ = s.db.Exec(`DELETE FROM traffic WHERE time<?`, before)
	_, _ = s.db.Exec(`DELETE FROM audit WHERE time<?`, before-365*24*3600)
}
