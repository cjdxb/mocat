package node

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

// Config 节点本地配置（N-04）：只包含少量启动参数，转发规则由控制端下发。
type Config struct {
	Listen   string   `json:"listen"`              // 管理端口监听地址，如 0.0.0.0:9443
	Token    string   `json:"token"`               // 节点凭据
	AllowIPs []string `json:"allow_ips,omitempty"` // 允许访问管理端口的来源 IP / CIDR（A-05，可选）
	LogLevel string   `json:"log_level,omitempty"` // debug/info/warn/error
	StateDir string   `json:"state_dir,omitempty"` // 状态目录：证书、缓存配置等
	BinDir   string   `json:"bin_dir,omitempty"`   // fakehttp/fakesip 所在目录，默认与 mocat-node 同目录

	path string
}

// DefaultConfigPath 默认配置文件路径。
const DefaultConfigPath = "/etc/mocat/node.json"

// LoadConfig 读取配置文件并补全默认值。
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
	}
	c.path = path
	c.fill()
	if len(c.Token) < 16 {
		return nil, fmt.Errorf("配置文件 %s 中 token 缺失或过短（至少 16 个字符）", path)
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return nil, fmt.Errorf("listen 地址不合法: %w", err)
	}
	return c, nil
}

func (c *Config) fill() {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:9443"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/mocat"
	}
	if c.BinDir == "" {
		if exe, err := os.Executable(); err == nil {
			c.BinDir = filepath.Dir(exe)
		}
	}
}

// Save 写回配置文件（权限 0600，因含 token）。
func (c *Config) Save() error {
	return SaveConfig(c.path, c)
}

// SaveConfig 写入配置文件。
func SaveConfig(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ManagementPort 返回管理端口号。
func (c *Config) ManagementPort() int {
	_, p, _ := net.SplitHostPort(c.Listen)
	n, _ := strconv.Atoi(p)
	return n
}
