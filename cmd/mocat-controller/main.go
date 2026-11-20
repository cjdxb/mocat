// mocat-controller：mocat 控制端（Web 管理界面 + 节点管理）。
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"mocat/internal/controller"
	"mocat/internal/version"
)

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-version" || args[0] == "-v") {
		fmt.Println(version.String("mocat-controller"))
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	c := fs.String("c", controller.DefaultControllerConfigPath, "配置文件路径（不存在时使用默认值）")
	user := fs.String("user", "admin", "要重置密码的用户名（reset-password）")
	_ = fs.Parse(args)
	var err error
	switch cmd {
	case "run":
		err = controller.Run(*c)
	case "reset-password":
		var pw string
		pw, err = controller.ResetPassword(*c, *user)
		if err == nil {
			fmt.Printf("用户 %s 的新密码: %s\n", *user, pw)
		}
	default:
		fmt.Fprintf(os.Stderr, `用法:
  mocat-controller [run] [-c 配置文件]                 启动控制端
  mocat-controller reset-password [-user admin] [-c 配置文件]  重置密码
  mocat-controller --version                           显示版本
`)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}
