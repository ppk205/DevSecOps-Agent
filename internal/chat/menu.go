package chat

import (
	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
	"strings"
)

type menuItem struct{ name, description string }

var commandMenu = []menuItem{
	{"model", "List or switch added models; /model add opens the form"},
	{"mode", "Choose ask or auto; /mode auto asks for confirmation"},
	{"cost", "Show session tokens and cost"},
	{"review", "Review proposed findings with a human decision"},
	{"export", "Export session reports"},
	{"resume", "Resume a session JSONL path"},
	{"clear", "Clear chat through the host"},
	{"baseline", "Open testing-only baseline comparison"},
	{"keys", "Manage keys for added models"},
	{"remote", "Browser remote: /remote on or /remote off"},
	{"help", "Show keys and command descriptions"},
	{"quit", "Close this client and leave pending steps undecided"},
}

func (m Model) menuOpen() bool {
	return strings.HasPrefix(m.input.Value(), "/") && !strings.ContainsAny(m.input.Value(), " \t")
}
func (m Model) filteredMenu() []menuItem {
	query := strings.TrimPrefix(m.input.Value(), "/")
	out := []menuItem{}
	for _, item := range commandMenu {
		if strings.HasPrefix(item.name, query) {
			out = append(out, item)
		}
	}
	return out
}
func (m Model) runCommand(name string, args []string) (tea.Model, tea.Cmd) {
	m.input.SetValue("")
	m.menuIndex = 0
	switch name {
	case "baseline":
		return m.activate("tab:1")
	case "keys":
		return m.activate("tab:2")
	case "help":
		m.help = true
		return m, nil
	case "quit":
		return m, m.quit()
	case "model":
		if len(args) > 0 && args[0] == "add" {
			return m.startAction("model:add")
		}
	case "mode":
		if len(args) > 0 && args[0] == "auto" {
			m.confirmAuto = true
			return m, nil
		}
	}
	if args == nil {
		args = []string{}
	}
	m.send(bridge.ChatMessage{"type": "command", "name": name, "args": args})
	return m, nil
}
