package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config 控制端配置。
type Config struct {
	Listen    string `json:"listen"`               // Web 监听地址，如 0.0.0.0:8443
	DataDir   string `json:"data_dir"`             // 数据目录（数据库、密钥、证书、节点安装包）
	TLSCert   string `json:"tls_cert,omitempty"`   // 自定义证书；为空时自动生成自签名证书（C-04）
	TLSKey    string `json:"tls_key,omitempty"`    //
	PublicURL string `json:"public_url,omitempty"` // 节点安装命令中使用的控制端地址，如 https://1.2.3.4:8443
	LogLevel  string `json:"log_level,omitempty"`
}

// DefaultControllerConfigPath 默认配置文件路径。
const DefaultControllerConfigPath = "/etc/mocat/controller.json"

// LoadConfig 读取配置；文件不存在时使用默认值。
func LoadConfig(path string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
		}
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8443"
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/mocat-controller"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.TLSCert == "" {
		c.TLSCert = filepath.Join(c.DataDir, "controller.crt")
		c.TLSKey = filepath.Join(c.DataDir, "controller.key")
	}
	return c, nil
}
