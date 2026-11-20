package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mocat/internal/logx"
	"mocat/internal/tlsutil"
	"mocat/internal/version"
)

// Run 启动控制端。
func Run(configPath string) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	log := logx.Setup(os.Stderr, cfg.LogLevel, nil)
	log.Info("mocat 控制端启动", "version", version.Version, "listen", cfg.Listen, "data_dir", cfg.DataDir)

	store, err := OpenStore(cfg.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	auth := NewAuth(store)
	pw, err := auth.EnsureAdmin()
	if err != nil {
		return err
	}
	if pw != "" {
		// C-41：首次启动生成随机初始密码并打印（只打印这一次）。
		log.Warn("已创建管理员账号，请登录后立即修改密码", "username", "admin", "password", pw)
	}

	host, _, _ := net.SplitHostPort(cfg.Listen)
	hn, _ := os.Hostname()
	cert, err := tlsutil.LoadOrCreate(cfg.TLSCert, cfg.TLSKey, "mocat-controller", []string{host, hn, "localhost", "127.0.0.1"})
	if err != nil {
		return err
	}
	log.Info("Web 证书", "sha256", tlsutil.Fingerprint(cert.Certificate[0]))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	syncer := NewSyncer(store, log)
	if err := syncer.BumpVersions(); err != nil {
		log.Warn("初始化配置版本失败", "err", err)
	}
	go syncer.Run(ctx)

	srv := NewServer(cfg, store, syncer, auth, cert, log)
	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServeTLS("", "") }()
	log.Info("Web 管理界面已启动", "url", "https://"+cfg.Listen)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	log.Info("已退出")
	return nil
}

// ResetPassword 命令行重置 admin 密码（忘记密码时使用）。
func ResetPassword(configPath, user string) (string, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return "", err
	}
	store, err := OpenStore(cfg.DataDir)
	if err != nil {
		return "", err
	}
	defer store.Close()
	pw := RandToken(8)
	h, err := hashPassword(pw)
	if err != nil {
		return "", err
	}
	return pw, store.SetUser(user, h)
}
