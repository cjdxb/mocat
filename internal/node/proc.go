package node

import (
	"bufio"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Proc 托管一个子进程：异常退出自动重启（带退避），Stop 时终止（N-14、N-52）。
type Proc struct {
	name string
	path string
	args []string
	log  *slog.Logger

	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	lastErr   string
	restarts  int
	stopping  bool
	stopCh    chan struct{}
	stoppedCh chan struct{}
	startedAt time.Time
	gid       *uint32
}

// SetGID 让子进程以指定属组运行（保持 uid 不变），须在 Start 之前调用。
func (p *Proc) SetGID(gid uint32) { p.gid = &gid }

// NewProc 创建托管进程（尚未启动）。
func NewProc(name, path string, args []string, log *slog.Logger) *Proc {
	return &Proc{name: name, path: path, args: args, log: log.With("proc", name)}
}

// Start 启动并开始监管。
func (p *Proc) Start() {
	p.mu.Lock()
	p.stopCh = make(chan struct{})
	p.stoppedCh = make(chan struct{})
	p.mu.Unlock()
	go p.loop()
}

func (p *Proc) loop() {
	defer close(p.stoppedCh)
	backoff := time.Second
	for {
		p.mu.Lock()
		if p.stopping {
			p.mu.Unlock()
			return
		}
		cmd := exec.Command(p.path, p.args...)
		// 新进程组；节点进程意外退出时由内核杀掉子进程，避免残留（N-06）。
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		if p.gid != nil {
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(syscall.Geteuid()), Gid: *p.gid, NoSetGroups: true}
		}
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		err := cmd.Start()
		if err != nil {
			p.lastErr = err.Error()
			p.running = false
			p.mu.Unlock()
			p.log.Error("启动子进程失败", "err", err)
		} else {
			p.cmd = cmd
			p.running = true
			p.startedAt = time.Now()
			p.mu.Unlock()
			p.log.Info("子进程已启动", "pid", cmd.Process.Pid, "args", p.args)
			var wg sync.WaitGroup
			wg.Add(2)
			go p.pipe(stdout, &wg)
			go p.pipe(stderr, &wg)
			wg.Wait()
			werr := cmd.Wait()
			p.mu.Lock()
			p.running = false
			p.cmd = nil
			ranFor := time.Since(p.startedAt)
			if p.stopping {
				p.mu.Unlock()
				return
			}
			if werr != nil {
				p.lastErr = werr.Error()
			} else {
				p.lastErr = "进程意外退出"
			}
			p.restarts++
			p.mu.Unlock()
			p.log.Warn("子进程异常退出，将自动重启", "err", p.lastErr, "ran", ranFor.Round(time.Millisecond).String())
			if ranFor > time.Minute {
				backoff = time.Second
			}
		}
		select {
		case <-time.After(backoff):
		case <-p.stopCh:
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (p *Proc) pipe(r io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	if r == nil {
		return
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		p.log.Info(sc.Text())
	}
}

// Stop 终止进程并等待监管协程退出（先 SIGTERM，3 秒后 SIGKILL）。
func (p *Proc) Stop() {
	p.mu.Lock()
	if p.stopping || p.stoppedCh == nil {
		p.mu.Unlock()
		return
	}
	p.stopping = true
	close(p.stopCh)
	cmd := p.cmd
	ch := p.stoppedCh
	p.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-ch
		}
	} else {
		<-ch
	}
	p.log.Info("子进程已停止")
}

// Running 进程当前是否在运行。
func (p *Proc) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// Uptime 本次运行时长。
func (p *Proc) Uptime() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return 0
	}
	return time.Since(p.startedAt)
}

// LastError 最近一次失败原因。
func (p *Proc) LastError() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErr
}
