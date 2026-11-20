package node

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"mocat/internal/api"
)

// Env 启动检查结果（N-03）。
type Env struct {
	Socat     string // 可执行文件路径，空表示不可用
	Nft       string
	FakeHTTP  string
	FakeSIP   string
	Conntrack string
	HasFib    bool // 内核是否支持 nft fib 表达式
	HasQueue  bool // 内核是否支持 NFQUEUE
	HasIPv6   bool // 本机是否启用了 IPv6
	Root      bool
	Backends  []api.BackendInfo
	Warnings  []string
}

const (
	capNetAdmin = 12
	capNetRaw   = 13
)

func hasCaps() (admin, raw bool) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "CapEff:") {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			if err != nil {
				return false, false
			}
			return v&(1<<capNetAdmin) != 0, v&(1<<capNetRaw) != 0
		}
	}
	return false, false
}

func findBin(name, binDir string) string {
	if binDir != "" {
		p := filepath.Join(binDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func cmdOutput(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// CheckEnv 检查运行条件，缺失时给出明确提示。
func CheckEnv(binDir string) *Env {
	e := &Env{}
	admin, raw := hasCaps()
	e.Root = os.Geteuid() == 0
	if !e.Root && !(admin && raw) {
		e.Warnings = append(e.Warnings, "需要以 root 运行或具备 CAP_NET_ADMIN 与 CAP_NET_RAW 权限")
	}

	// nft
	e.Nft = findBin("nft", "")
	nftInfo := api.BackendInfo{Name: "nft"}
	if e.Nft != "" {
		v, err := cmdOutput(3*time.Second, e.Nft, "--version")
		if err == nil {
			nftInfo.Available, nftInfo.Path, nftInfo.Version = true, e.Nft, firstLine(v)
		} else {
			nftInfo.Note = "nft 无法执行: " + v
			e.Nft = ""
		}
	} else {
		nftInfo.Note = "未找到 nft 命令，请安装 nftables 软件包"
	}
	if e.Nft == "" {
		e.Warnings = append(e.Warnings, "nftables 不可用：nft 后端、伪装和流量统计都无法工作")
	}

	// NFQUEUE
	_ = exec.Command("modprobe", "nfnetlink_queue").Run()
	if _, err := os.Stat("/proc/net/netfilter/nfnetlink_queue"); err == nil {
		e.HasQueue = true
	} else {
		e.Warnings = append(e.Warnings, "内核未加载 nfnetlink_queue（NFQUEUE），伪装功能不可用")
	}
	_ = exec.Command("modprobe", "nf_conntrack").Run()

	// IPv6 被禁用（如 ipv6.disable=1）时该文件不存在，socat 不能双栈监听。
	if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
		e.HasIPv6 = true
	}

	if e.Nft != "" && e.Root {
		e.HasFib = probeFib(e.Nft)
	}

	// socat
	e.Socat = findBin("socat", "")
	si := api.BackendInfo{Name: "socat"}
	if e.Socat != "" {
		v, _ := cmdOutput(3*time.Second, e.Socat, "-V")
		si.Available, si.Path = true, e.Socat
		for _, l := range strings.Split(v, "\n") {
			if strings.Contains(l, "socat version") {
				si.Version = strings.TrimSpace(l)
				break
			}
		}
	} else {
		si.Note = "未找到 socat，请安装 socat 软件包"
		e.Warnings = append(e.Warnings, "socat 不可用：socat 后端规则无法运行")
	}

	// fakehttp / fakesip
	e.FakeHTTP = findBin("fakehttp", binDir)
	e.FakeSIP = findBin("fakesip", binDir)
	fh := api.BackendInfo{Name: "fakehttp", Available: e.FakeHTTP != "", Path: e.FakeHTTP}
	fs := api.BackendInfo{Name: "fakesip", Available: e.FakeSIP != "", Path: e.FakeSIP}
	if e.FakeHTTP == "" {
		fh.Note = "未找到 fakehttp（应随发行包放在 mocat-node 同目录）"
		e.Warnings = append(e.Warnings, fh.Note)
	}
	if e.FakeSIP == "" {
		fs.Note = "未找到 fakesip（应随发行包放在 mocat-node 同目录）"
		e.Warnings = append(e.Warnings, fs.Note)
	}

	// conntrack（可选，用于 N-2A 清理已有连接）
	e.Conntrack = findBin("conntrack", "")
	ct := api.BackendInfo{Name: "conntrack", Available: e.Conntrack != "", Path: e.Conntrack}
	if e.Conntrack == "" {
		ct.Note = "未找到 conntrack 命令（conntrack-tools），规则启用时无法清理已有连接"
		e.Warnings = append(e.Warnings, ct.Note)
	}

	nfq := api.BackendInfo{Name: "nfqueue", Available: e.HasQueue}
	fib := api.BackendInfo{Name: "nft-fib", Available: e.HasFib, Note: "可选：用于 nft 后端只匹配发往本机的报文"}
	e.Backends = []api.BackendInfo{nftInfo, si, fh, fs, ct, nfq, fib}
	return e
}

func probeFib(nft string) bool {
	script := "table inet mocat_probe { chain c { type filter hook prerouting priority 0; fib daddr type local accept; } }\ndelete table inet mocat_probe\n"
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	err := cmd.Run()
	if err != nil {
		_ = exec.Command(nft, "delete", "table", "inet", "mocat_probe").Run()
	}
	return err == nil
}

// SysInfo 采集系统信息。
func SysInfo() api.SystemInfo {
	s := api.SystemInfo{OS: runtime.GOOS, Arch: runtime.GOARCH}
	s.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				s.Distro = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
			}
		}
	}
	return s
}

// setSysctl 设置 sysctl，返回原值。
func setSysctl(name, val string) (old string, err error) {
	// 与 sysctl 命令一致：名字中的 “.” 是层级分隔，“/” 对应接口名里的 “.”。
	p := "/proc/sys/" + strings.Map(func(r rune) rune {
		switch r {
		case '.':
			return '/'
		case '/':
			return '.'
		}
		return r
	}, name)
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	old = strings.TrimSpace(string(b))
	if old == val {
		return old, nil
	}
	if err := os.WriteFile(p, []byte(val), 0o644); err != nil {
		return old, fmt.Errorf("设置 %s=%s 失败: %w", name, val, err)
	}
	return old, nil
}
