package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"mocat/internal/api"
	"mocat/internal/tlsutil"
)

// ErrFingerprintMismatch 节点证书指纹与固定的指纹不一致。
var ErrFingerprintMismatch = errors.New("节点证书指纹已变化，已拒绝连接")

// HTTPError 节点返回的非 2xx 响应。
type HTTPError struct {
	Code int
	Body api.ErrorResponse
}

func (e *HTTPError) Error() string {
	if e.Body.Error != "" {
		return fmt.Sprintf("节点返回 %d: %s", e.Code, e.Body.Error)
	}
	return fmt.Sprintf("节点返回 %d", e.Code)
}

// NodeClient 访问单个节点管理端口的客户端。
type NodeClient struct {
	base     string
	token    string
	pinned   string // 期望的证书指纹，为空表示首次连接（记录指纹）
	seenFP   string
	http     *http.Client
	mismatch string
}

// NewNodeClient 创建客户端。控制端校验节点证书：自签名证书无法走 CA 校验，因此固定证书指纹（A-04）。
func NewNodeClient(n Node, token string) *NodeClient {
	c := &NodeClient{base: "https://" + net.JoinHostPort(n.Host, strconv.Itoa(n.Port)), token: token, pinned: n.CertFP}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 由下面的 VerifyPeerCertificate 做指纹校验
			MinVersion:         tls.VersionTLS12,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("节点未提供证书")
				}
				fp := tlsutil.Fingerprint(raw[0])
				c.seenFP = fp
				if c.pinned != "" && fp != c.pinned {
					c.mismatch = fp
					return ErrFingerprintMismatch
				}
				return nil
			},
		},
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
	}
	c.http = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return c
}

// SeenFingerprint 本次连接看到的证书指纹。
func (c *NodeClient) SeenFingerprint() string { return c.seenFP }

// Mismatch 不一致时看到的新指纹。
func (c *NodeClient) Mismatch() string { return c.mismatch }

func (c *NodeClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if c.mismatch != "" {
			return ErrFingerprintMismatch
		}
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		he := &HTTPError{Code: resp.StatusCode}
		_ = json.Unmarshal(data, &he.Body)
		return he
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *NodeClient) Status(ctx context.Context) (*api.NodeStatus, error) {
	var s api.NodeStatus
	return &s, c.do(ctx, http.MethodGet, "/api/v1/status", nil, &s)
}

func (c *NodeClient) Stats(ctx context.Context) (*api.NodeStats, error) {
	var s api.NodeStats
	return &s, c.do(ctx, http.MethodGet, "/api/v1/stats", nil, &s)
}

func (c *NodeClient) PutConfig(ctx context.Context, cfg api.NodeConfig) error {
	return c.do(ctx, http.MethodPut, "/api/v1/config", cfg, nil)
}

func (c *NodeClient) Logs(ctx context.Context, n int) ([]api.LogEntry, error) {
	var l []api.LogEntry
	return l, c.do(ctx, http.MethodGet, "/api/v1/logs?n="+strconv.Itoa(n), nil, &l)
}

func (c *NodeClient) SetToken(ctx context.Context, token string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/token", api.TokenUpdate{Token: token}, nil)
}
