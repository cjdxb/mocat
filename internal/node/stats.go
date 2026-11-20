package node

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// queueInfo /proc/net/netfilter/nfnetlink_queue 中一个队列的信息。
type queueInfo struct {
	PortID      uint32
	QueueDrop   uint64
	UserDropped uint64
}

// readQueues 读取已绑定的 NFQUEUE 队列。伪装进程就绪 = 其队列号出现在这里（N-28）。
func readQueues() map[int]queueInfo {
	res := map[int]queueInfo{}
	b, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return res
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 7 {
			continue
		}
		q, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		pid, _ := strconv.ParseUint(f[1], 10, 32)
		qd, _ := strconv.ParseUint(f[5], 10, 64)
		ud, _ := strconv.ParseUint(f[6], 10, 64)
		res[q] = queueInfo{PortID: uint32(pid), QueueDrop: qd, UserDropped: ud}
	}
	return res
}

// countConns 按 ct mark 统计当前连接数（只计 mocat 标记的连接）。
// 优先读 /proc/net/nf_conntrack，不存在时用 conntrack -L。
func countConns(conntrackBin string) map[uint32]int {
	res := map[uint32]int{}
	var data []byte
	if b, err := os.ReadFile("/proc/net/nf_conntrack"); err == nil {
		data = b
	} else if conntrackBin != "" {
		out, err := exec.Command(conntrackBin, "-L", "-o", "extended").Output()
		if err == nil {
			data = out
		}
		if out6, err := exec.Command(conntrackBin, "-L", "-f", "ipv6", "-o", "extended").Output(); err == nil {
			data = append(data, out6...)
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, " mark=")
		if i < 0 {
			continue
		}
		rest := line[i+6:]
		if j := strings.IndexByte(rest, ' '); j >= 0 {
			rest = rest[:j]
		}
		m, err := strconv.ParseUint(rest, 10, 32)
		if err != nil {
			continue
		}
		mark := uint32(m) & markMask
		if mark&0xff000000 != ruleMarkBase {
			continue
		}
		// TCP 中已关闭的连接不计入
		if strings.Contains(line, " TIME_WAIT ") || strings.Contains(line, " CLOSE ") || strings.Contains(line, " FIN_WAIT ") ||
			strings.Contains(line, " LAST_ACK ") || strings.Contains(line, " CLOSE_WAIT ") {
			continue
		}
		res[mark]++
	}
	return res
}
