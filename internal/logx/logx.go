// Package logx 提供结构化日志（slog）以及最近日志的环形缓冲。
package logx

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"mocat/internal/api"
)

// Ring 保存最近 N 条日志。
type Ring struct {
	mu   sync.Mutex
	buf  []api.LogEntry
	next int
	full bool
}

// NewRing 创建容量为 n 的环形缓冲。
func NewRing(n int) *Ring { return &Ring{buf: make([]api.LogEntry, n)} }

func (r *Ring) add(e api.LogEntry) {
	r.mu.Lock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

// Last 返回最近 n 条，按时间正序。
func (r *Ring) Last(n int) []api.LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var all []api.LogEntry
	if r.full {
		all = append(all, r.buf[r.next:]...)
	}
	all = append(all, r.buf[:r.next]...)
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	out := make([]api.LogEntry, len(all))
	copy(out, all)
	return out
}

// ParseLevel 解析日志级别字符串。
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Setup 初始化默认 logger：输出 JSON 到 w，同时写入 ring。
func Setup(w io.Writer, level string, ring *Ring) *slog.Logger {
	lv := ParseLevel(level)
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})
	var h slog.Handler = base
	if ring != nil {
		h = &ringHandler{Handler: base, ring: ring, level: lv}
	}
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

type ringHandler struct {
	slog.Handler
	ring  *Ring
	level slog.Level
	attrs []slog.Attr
}

func (h *ringHandler) Handle(ctx context.Context, rec slog.Record) error {
	var sb strings.Builder
	sb.WriteString(rec.Message)
	write := func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(a.Value.String())
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	rec.Attrs(write)
	t := rec.Time
	if t.IsZero() {
		t = time.Now()
	}
	h.ring.add(api.LogEntry{Time: t.UnixMilli(), Level: rec.Level.String(), Msg: sb.String()})
	return h.Handler.Handle(ctx, rec)
}

func (h *ringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ringHandler{Handler: h.Handler.WithAttrs(attrs), ring: h.ring, level: h.level,
		attrs: append(append([]slog.Attr{}, h.attrs...), attrs...)}
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	return &ringHandler{Handler: h.Handler.WithGroup(name), ring: h.ring, level: h.level, attrs: h.attrs}
}
