package controller

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 会话与登录限流（C-40 ~ C-43）。

const (
	sessionCookie = "mocat_session"
	sessionTTL    = 12 * time.Hour
)

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("mocat-dummy"), bcrypt.DefaultCost)

type session struct {
	user    string
	expires time.Time
}

// Auth 管理会话与登录失败限制。
type Auth struct {
	store *Store
	mu    sync.Mutex
	sess  map[string]*session
	fails map[string]*loginFail
}

type loginFail struct {
	count int
	first time.Time
	until time.Time
}

// NewAuth 创建认证管理器。
func NewAuth(store *Store) *Auth {
	return &Auth{store: store, sess: map[string]*session{}, fails: map[string]*loginFail{}}
}

// RandToken 生成随机十六进制串。
func RandToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EnsureAdmin 首次启动时创建 admin 账号并返回随机初始密码（C-41）；已有用户时返回空串。
func (a *Auth) EnsureAdmin() (string, error) {
	n, err := a.store.UserCount()
	if err != nil || n > 0 {
		return "", err
	}
	pw := RandToken(8)
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return pw, a.store.SetUser("admin", string(h))
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// Locked 来源 IP 是否因失败次数过多被锁定。
func (a *Auth) Locked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

// Login 校验用户名密码，成功返回会话 ID。10 分钟内失败 5 次锁定 10 分钟（C-43）。
func (a *Auth) Login(user, pass, ip string) (string, bool) {
	h, err := a.store.UserHash(user)
	ok := err == nil && bcrypt.CompareHashAndPassword([]byte(h), []byte(pass)) == nil
	if err != nil {
		// 防止通过响应时间探测用户名
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pass))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if !ok {
		f := a.fails[ip]
		if f == nil || now.Sub(f.first) > 10*time.Minute {
			f = &loginFail{first: now}
			a.fails[ip] = f
		}
		f.count++
		if f.count >= 5 {
			f.until = now.Add(10 * time.Minute)
			f.count, f.first = 0, now
		}
		return "", false
	}
	delete(a.fails, ip)
	id := RandToken(32)
	a.sess[id] = &session{user: user, expires: now.Add(sessionTTL)}
	for k, s := range a.sess {
		if now.After(s.expires) {
			delete(a.sess, k)
		}
	}
	return id, true
}

// User 根据会话 ID 返回用户名，并续期。
func (a *Auth) User(id string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sess[id]
	if s == nil || time.Now().After(s.expires) {
		delete(a.sess, id)
		return "", false
	}
	s.expires = time.Now().Add(sessionTTL)
	return s.user, true
}

// Logout 注销会话。
func (a *Auth) Logout(id string) {
	a.mu.Lock()
	delete(a.sess, id)
	a.mu.Unlock()
}

// ChangePassword 修改密码，并注销该用户的其他会话。
func (a *Auth) ChangePassword(user, oldPw, newPw, keepSession string) bool {
	h, err := a.store.UserHash(user)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(h), []byte(oldPw)) != nil {
		return false
	}
	nh, err := bcrypt.GenerateFromPassword([]byte(newPw), bcrypt.DefaultCost)
	if err != nil || a.store.SetUser(user, string(nh)) != nil {
		return false
	}
	a.mu.Lock()
	for k, s := range a.sess {
		if s.user == user && k != keepSession {
			delete(a.sess, k)
		}
	}
	a.mu.Unlock()
	return true
}
