// Package tlsutil 生成 / 加载自签名证书并计算指纹。
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoadOrCreate 加载 certFile/keyFile；若都不存在则生成自签名证书（有效期 10 年）。
func LoadOrCreate(certFile, keyFile, commonName string, hosts []string) (tls.Certificate, error) {
	_, e1 := os.Stat(certFile)
	_, e2 := os.Stat(keyFile)
	if errors.Is(e1, os.ErrNotExist) && errors.Is(e2, os.ErrNotExist) {
		if err := generate(certFile, keyFile, commonName, hosts); err != nil {
			return tls.Certificate{}, err
		}
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func generate(certFile, keyFile, cn string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"mocat"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Fingerprint 返回证书 DER 的 SHA-256 指纹（小写 hex，冒号分隔）。
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := hex.EncodeToString(sum[:])
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// SPKIPin 返回 curl --pinnedpubkey 使用的 sha256//base64 公钥指纹。
func SPKIPin(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}
