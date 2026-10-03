//go:build windows

package process

import (
	"os/exec"
	"strconv"
	"syscall"
)

func Configure(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000200}
}
func KillTree(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	kill := exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F")
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := kill.Run(); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
