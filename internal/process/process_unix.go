//go:build !windows

package process

import (
	"os/exec"
	"syscall"
)

func Configure(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func KillTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
