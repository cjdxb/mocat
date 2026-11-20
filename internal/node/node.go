// Package node 实现 mocat 节点（agent）。
package node

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"mocat/internal/logx"
	"mocat/internal/tlsutil"
	"mocat/internal/version"
)

// Run 启动节点并阻塞直到收到退出信号。
func Run(configPath string) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	ring := logx.NewRing(1000)
	log := logx.Setup(os.Stderr, cfg.LogLevel, ring)
	log.Info("mocat 节点启动", "version", version.Version, "config", configPath)

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}

	env := CheckEnv(cfg.BinDir)
	for _, w := range env.Warnings {
		log.Warn("运行条件检查: " + w)
	}

	// A-04：首次启动自动生成自签名证书。
	host, _ := os.Hostname()
	cert, err := tlsutil.LoadOrCreate(filepath.Join(cfg.StateDir, "node.crt"), filepath.Join(cfg.StateDir, "node.key"), "mocat-node "+host, nil)
	if err != nil {
		return err
	}
	log.Info("管理端口证书", "sha256", tlsutil.Fingerprint(cert.Certificate[0]))

	mgr := NewManager(cfg, env, log)
	// 清理上次异常退出可能残留的表，再按缓存配置恢复（N-05）。
	_ = nftDeleteTable(env.Nft)
	if c, err := mgr.LoadCache(); err == nil {
		log.Info("按本地缓存配置恢复转发", "version", c.Version)
		if err := mgr.Apply(*c, true); err != nil {
			log.Error("缓存配置无效", "err", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Warn("读取缓存配置失败", "err", err)
	} else {
		log.Info("没有缓存配置，等待控制端下发")
	}

	srv, err := NewServer(cfg, mgr, env, ring, log)
	if err != nil {
		mgr.Shutdown()
		return err
	}
	httpSrv, err := srv.ListenAndServe(cert)
	if err != nil {
		mgr.Shutdown()
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go mgr.Run(ctx)
	<-ctx.Done()

	log.Info("收到退出信号，清理中")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	mgr.Shutdown()
	log.Info("已退出")
	return nil
}

// Cleanup 清理 mocat 创建的 nftables 表（用于异常情况下手动清理）。
func Cleanup() error {
	env := &Env{Nft: findBin("nft", "")}
	slog.Info("删除 nftables 表 inet " + nftTable)
	return nftDeleteTable(env.Nft)
}
