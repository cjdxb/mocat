// mocat-node：mocat 转发节点。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mocat/internal/node"
	"mocat/internal/version"
)

func usage() {
	fmt.Fprintf(os.Stderr, `用法:
  mocat-node [run] [-c 配置文件]          启动节点（默认）
  mocat-node init -token T [-listen 地址] [-allow IP,...] [-c 配置文件]
                                          生成本地配置文件
  mocat-node check [-c 配置文件]          检查运行条件
  mocat-node cleanup                      删除 mocat 创建的 nftables 表
  mocat-node --version                    显示版本
`)
}

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-version" || args[0] == "-v") {
		fmt.Println(version.String("mocat-node"))
		return
	}
	var err error
	switch cmd {
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		c := fs.String("c", node.DefaultConfigPath, "配置文件路径")
		_ = fs.Parse(args)
		err = node.Run(*c)
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		c := fs.String("c", node.DefaultConfigPath, "配置文件路径")
		token := fs.String("token", "", "节点凭据（由控制端生成）")
		listen := fs.String("listen", "0.0.0.0:9443", "管理端口监听地址")
		allow := fs.String("allow", "", "允许访问管理端口的来源 IP/CIDR，逗号分隔（可选）")
		level := fs.String("log-level", "info", "日志级别")
		stateDir := fs.String("state-dir", "/var/lib/mocat", "状态目录")
		_ = fs.Parse(args)
		err = initConfig(*c, *token, *listen, *allow, *level, *stateDir)
	case "check":
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		c := fs.String("c", node.DefaultConfigPath, "配置文件路径")
		_ = fs.Parse(args)
		binDir := ""
		if cfg, e := node.LoadConfig(*c); e == nil {
			binDir = cfg.BinDir
		} else if exe, e := os.Executable(); e == nil {
			binDir = filepath.Dir(exe)
		}
		env := node.CheckEnv(binDir)
		for _, b := range env.Backends {
			st := "可用"
			if !b.Available {
				st = "不可用"
			}
			fmt.Printf("%-10s %-6s %s %s %s\n", b.Name, st, b.Path, b.Version, b.Note)
		}
		for _, w := range env.Warnings {
			fmt.Println("警告:", w)
		}
	case "cleanup":
		err = node.Cleanup()
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func initConfig(path, token, listen, allow, level, stateDir string) error {
	if token == "" {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		token = hex.EncodeToString(b)
		fmt.Println("未指定 -token，已随机生成:", token)
	}
	cfg := &node.Config{Listen: listen, Token: token, LogLevel: level, StateDir: stateDir}
	for _, a := range strings.Split(allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			cfg.AllowIPs = append(cfg.AllowIPs, a)
		}
	}
	if err := node.SaveConfig(path, cfg); err != nil {
		return err
	}
	fmt.Println("已写入配置文件:", path)
	return nil
}
