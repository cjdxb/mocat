// Package version 保存构建时注入的版本信息。
package version

import (
	"fmt"
	"runtime"
)

// 通过 -ldflags "-X mocat/internal/version.Version=..." 注入。
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String 返回 --version 输出。
func String(component string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s/%s, %s)",
		component, Version, Commit, Date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
