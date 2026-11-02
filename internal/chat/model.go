// Package chat is a display and relay client for the Python session host.
// It has no authority to approve gates or change finding statuses.
package chat

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
)

type Host interface {
	Events() <-chan bridge.ChatEvent
	Send(bridge.ChatMessage) error
	Err() error
	Close()
}

const (
	startScreen = iota
	chatScreen
)
const (
	tabChat = iota
	tabBaseline
	tabKeys
)

type hostEvent struct {
	event      bridge.ChatEvent
	generation int
}
type disconnectedMsg struct{ generation int }
type restartedMsg struct {
	host Host
	err  error
}

type Model struct {
	host         Host
	baseline     tea.Model
	baselineInit bool
	// Restart starts a fresh owned host. The session path comes from ready.
	Restart                                                     func() (Host, error)
	width, height                                               int
	screen, tab                                                 int
	input, target                                               textinput.Model
	blocks                                                      []block
	offset                                                      int
	busy, disconnected, restarting                              bool
	generation                                                  int
	dialog                                                      *dialog
	form                                                        *modelForm
	models                                                      []modelEntry
	templates                                                   []templateEntry
	startFocus, modelIndex, modelIDIndex, keysIndex, keysAction int
	startMode                                                   string
	starting                                                    bool
	status                                                      readyInfo
	tokens                                                      int
	cost                                                        float64
	notice                                                      string
	sessionPath                                                 string
	menuIndex                                                   int
	help, confirmAuto, quitArmed                                bool
	remoteURL                                                   string
	pendingEcho                                                 string
	pending                                                     []pendingReview
	harnessFindings, baselineFindings                           []Finding
	comparison                                                  *Comparison
	comparing                                                   bool
}

type readyInfo struct {
	Target      string `json:"target"`
	Provider    string `json:"provider"`
	Model       string `json:"model"`
	Mode        string `json:"mode"`
	Local       bool   `json:"local"`
	Commit      string `json:"commit"`
	Session     string `json:"session"`
	SessionPath string `json:"session_path"`
	SessionLog  string `json:"session_log"`
}
type pendingReview struct {
	ID     string   `json:"id"`
	Ref    string   `json:"ref"`
	Files  []string `json:"files"`
	Source string   `json:"source"`
}

func New(host Host, baseline tea.Model) Model {
	in, target := textinput.New(), textinput.New()
	in.CharLimit = 32000
	in.Placeholder = "Ask AI support to investigate…"
	in.SetWidth(70)
	in.Focus()
	target.CharLimit = 4096
	target.Placeholder = "Path to target"
	target.SetWidth(64)
	return Model{host: host, baseline: baseline, width: 80, height: 24, input: in, target: target, startFocus: 3, startMode: "ask", status: readyInfo{Mode: "ask"}}
}
func listen(h Host, generation int) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-h.Events()
		if !ok {
			return disconnectedMsg{generation}
		}
		return hostEvent{e, generation}
	}
}
func (m Model) Init() tea.Cmd {
	return tea.Batch(listen(m.host, m.generation), func() tea.Msg {
		if err := m.host.Send(bridge.ChatMessage{"type": "hello"}); err != nil {
			return disconnectedMsg{m.generation}
		}
		return nil
	})
}
func (m Model) Close() {
	if m.host != nil {
		m.host.Close()
	}
}
func (m *Model) send(message bridge.ChatMessage) {
	if m.disconnected {
		return
	}
	if err := m.host.Send(message); err != nil {
		m.disconnect()
	}
}
func (m *Model) disconnect() {
	if m.dialog != nil {
		m.appendBlock("notice", m.dialog.gate+" left undecided")
		m.dialog = nil
	}
	m.disconnected = true
	m.busy = false
	m.starting = false
	m.form = nil
	m.confirmAuto = false
	m.notice = "Host disconnected. Pending steps are undecided."
}
func (m *Model) resize() {
	m.input.SetWidth(max(1, m.width-4))
	m.target.SetWidth(max(1, m.width-12))
	if m.dialog != nil {
		m.dialog.resize(m.width, m.bodyHeight())
	}
	if m.form != nil {
		for i := range m.form.fields {
			m.form.fields[i].SetWidth(max(1, m.width-19))
		}
	}
}
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = v.Width, v.Height
		m.resize()
		if m.baseline != nil {
			var cmd tea.Cmd
			m.baseline, cmd = m.baseline.Update(tea.WindowSizeMsg{Width: m.width, Height: max(1, m.bodyHeight()-3)})
			return m, cmd
		}
	case hostEvent:
		if v.generation != m.generation {
			return m, nil
		}
		m.receive(v.event)
		return m, listen(m.host, m.generation)
	case bridge.ChatEvent:
		m.receive(v)
	case disconnectedMsg:
		if v.generation == m.generation {
			m.disconnect()
		}
	case restartedMsg:
		m.restarting = false
		if v.err != nil {
			m.notice = "Restart failed. Press r to retry."
			return m, nil
		}
		m.host = v.host
		m.generation++
		m.disconnected = false
		m.notice = "Resuming session…"
		m.send(bridge.ChatMessage{"type": "hello"})
		if m.sessionPath != "" {
			m.starting = true
			m.send(bridge.ChatMessage{"type": "start", "target": m.status.Target, "model": m.status.Provider + ":" + m.status.Model, "mode": m.status.Mode, "resume": m.sessionPath})
		} else {
			m.screen = startScreen
		}
		return m, listen(m.host, m.generation)
	case comparisonMsg:
		m.baselineFindings = v.findings
		if v.err != nil {
			m.notice = "Comparison unavailable: " + v.err.Error()
			m.comparing = false
		} else {
			m.updateComparison()
		}
	case tea.BlurMsg:
		m.leaveDialog()
		m.confirmAuto = false
	case tea.KeyPressMsg:
		return m.key(v)
	case tea.PasteMsg:
		return m.textInput(v)
	case tea.MouseClickMsg:
		if v.Button != tea.MouseLeft {
			return m, nil
		}
		_, hits := m.render()
		for _, h := range hits {
			if v.Y == h.y && v.X >= h.x && v.X < h.x+h.width {
				return m.activate(h.action)
			}
		}
		if m.tab == tabBaseline && m.baseline != nil && m.form == nil && m.dialog == nil && !m.help && !m.confirmAuto && v.Y >= 5 {
			v.Y -= 5
			var cmd tea.Cmd
			m.baseline, cmd = m.baseline.Update(v)
			return m, cmd
		}
	case tea.MouseWheelMsg:
		delta := 3
		if v.Button == tea.MouseWheelUp {
			delta = -3
		}
		if m.dialog != nil {
			m.dialog.scroll(delta)
		} else if m.tab == tabChat {
			m.scroll(delta)
		} else if m.tab == tabKeys {
			m.keysIndex = max(0, min(len(m.models)-1, m.keysIndex+delta))
		} else if m.baseline != nil {
			var cmd tea.Cmd
			m.baseline, cmd = m.baseline.Update(v)
			return m, cmd
		}
	default:
		if m.form != nil {
			return m.updateForm(msg)
		}
		if m.dialog != nil && m.dialog.form != "" {
			var cmd tea.Cmd
			m.dialog.input, cmd = m.dialog.input.Update(msg)
			return m, cmd
		}
		if m.baseline != nil && m.baselineInit {
			var cmd tea.Cmd
			m.baseline, cmd = m.baseline.Update(msg)
			return m, cmd
		}
		if m.screen == startScreen && m.startFocus == 0 {
			var cmd tea.Cmd
			m.target, cmd = m.target.Update(msg)
			return m, cmd
		}
		if m.screen == chatScreen && !m.busy && !m.disconnected {
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

func (m *Model) receive(e bridge.ChatEvent) {
	var data map[string]json.RawMessage
	if json.Unmarshal(e.Raw, &data) != nil {
		m.disconnect()
		return
	}
	str := func(k string) string { var s string; _ = json.Unmarshal(data[k], &s); return s }
	switch e.Type {
	case "models":
		previous := m.modelSpec()
		_ = json.Unmarshal(data["items"], &m.models)
		_ = json.Unmarshal(data["templates"], &m.templates)
		m.modelIndex = min(m.modelIndex, max(0, len(m.models)-1))
		m.keysIndex = min(m.keysIndex, max(0, len(m.models)-1))
		m.modelIDIndex = 0
		if selected := m.selectedModel(); selected != nil {
			for i, id := range selected.Models {
				if id == selected.DefaultModel {
					m.modelIDIndex = i
				}
			}
		}
		for i, entry := range m.models {
			for j, id := range entry.Models {
				if previous == entry.Alias+":"+id {
					m.modelIndex = i
					m.modelIDIndex = j
				}
			}
		}
		if len(m.models) > 0 && m.startFocus == 3 {
			m.startFocus = 0
			m.target.Focus()
		}
	case "ready":
		_ = json.Unmarshal(e.Raw, &m.status)
		m.screen = chatScreen
		m.starting = false
		m.busy = false
		if m.status.Session != "" {
			m.sessionPath = m.status.Session
		}
		if m.status.SessionPath != "" {
			m.sessionPath = m.status.SessionPath
		}
		if m.status.SessionLog != "" {
			m.sessionPath = m.status.SessionLog
		}
		m.notice = "Session ready · " + m.status.Commit
		m.input.Focus()
	case "text_delta":
		if str("role") == "user" {
			if m.pendingEcho == str("text") {
				m.pendingEcho = ""
			} else {
				m.appendBlock("you", str("text"))
			}
			m.busy = true
		} else {
			m.appendBlock("AI hỗ trợ", str("text"))
		}
	case "tool_call":
		m.busy = true
		m.blocks = append(m.blocks, block{role: "tool", id: str("id"), text: str("name"), detail: prettyJSON(data["arguments"])})
		m.follow()
	case "tool_result":
		found := false
		for i := len(m.blocks) - 1; i >= 0; i-- {
			if m.blocks[i].role == "tool" && m.blocks[i].id == str("id") {
				m.blocks[i].text = str("name") + " · " + str("summary")
				m.blocks[i].detail += "\n" + prettyJSON(data["result"])
				found = true
				break
			}
		}
		if !found {
			m.blocks = append(m.blocks, block{role: "tool", id: str("id"), text: str("name") + " · " + str("summary"), detail: prettyJSON(data["result"])})
		}
		m.follow()
	case "permission_request":
		m.dialog = newDialog(e.Raw)
		m.tab = tabChat
		m.form = nil
		m.help = false
		m.confirmAuto = false
		m.resize()
	case "gate_result":
		if m.dialog != nil && m.dialog.requestID == str("request_id") {
			m.dialog = nil
		}
		m.appendBlock("gate", str("gate")+" · "+str("choice")+" · "+str("person"))
	case "usage":
		_ = json.Unmarshal(data["total_tokens"], &m.tokens)
		_ = json.Unmarshal(data["total_cost_usd"], &m.cost)
	case "done":
		m.busy = false
		m.starting = false
		m.notice = "Turn " + str("reason")
	case "error":
		m.notice = str("message")
		m.appendBlock("error", m.notice)
		m.starting = false
	case "remote":
		m.remoteURL = str("url")
		if m.remoteURL != "" {
			m.appendBlock("remote", m.remoteURL+"\n[ copy link ] (terminal clipboard)")
		} else {
			m.appendBlock("remote", "Remote off")
		}
	case "pending":
		_ = json.Unmarshal(data["items"], &m.pending)
	case "findings":
		m.harnessFindings = parseFindings(data["items"])
		m.updateComparison()
	}
}

func (m Model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if key == "ctrl+c" {
		if m.quitArmed {
			return m, m.quit()
		}
		m.quitArmed = true
		m.leaveDialog()
		m.send(bridge.ChatMessage{"type": "interrupt"})
		m.notice = "Press Ctrl+C again to quit."
		return m, nil
	}
	m.quitArmed = false
	if m.width < 60 || m.height < 18 {
		return m, nil
	}
	if m.disconnected {
		if key == "r" {
			return m.activate("restart")
		}
		return m, nil
	}
	if m.dialog != nil {
		return m.dialogKey(k)
	}
	if m.form != nil {
		return m.formKey(k)
	}
	if m.confirmAuto {
		if key == "y" {
			m.confirmAuto = false
			m.send(bridge.ChatMessage{"type": "command", "name": "mode", "args": []string{"auto", "confirm"}})
		}
		if key == "n" || key == "esc" {
			m.confirmAuto = false
		}
		return m, nil
	}
	if m.help {
		if key == "esc" || key == "?" || key == "enter" {
			m.help = false
		}
		return m, nil
	}
	if key == "esc" {
		if m.tab != tabChat {
			m.tab = tabChat
			return m, nil
		}
		if m.menuOpen() {
			m.input.SetValue("")
			return m, nil
		}
		m.send(bridge.ChatMessage{"type": "interrupt"})
		m.notice = "Interrupt requested"
		return m, nil
	}
	if key == "?" && (m.input.Value() == "" || m.screen == startScreen) {
		m.help = true
		return m, nil
	}
	if key == "ctrl+1" {
		return m.activate("tab:0")
	}
	if key == "ctrl+2" {
		return m.activate("tab:1")
	}
	if key == "ctrl+3" {
		return m.activate("tab:2")
	}
	if m.tab == tabBaseline {
		if key == "ctrl+b" {
			return m.activate("baseline:compare")
		}
		if m.baseline != nil {
			var cmd tea.Cmd
			m.baseline, cmd = m.baseline.Update(k)
			return m, cmd
		}
		return m, nil
	}
	if m.tab == tabKeys {
		return m.keysKey(k)
	}
	if len(m.pending) > 0 && m.input.Value() == "" && m.screen == chatScreen {
		if key == "r" {
			return m.activate("pending:review:" + m.pending[0].ID)
		}
		if key == "x" {
			return m.activate("pending:dismiss:" + m.pending[0].ID)
		}
	}
	if m.screen == startScreen {
		return m.startKey(k)
	}
	if m.menuOpen() {
		options := m.filteredMenu()
		if key == "down" || key == "up" {
			delta := 1
			if key == "up" {
				delta = -1
			}
			m.menuIndex = (m.menuIndex + delta + max(1, len(options))) % max(1, len(options))
			return m, nil
		}
		if key == "enter" && len(options) > 0 {
			return m.runCommand(options[min(m.menuIndex, len(options)-1)].name, nil)
		}
	}
	if key == "pgdown" {
		m.scroll(m.bodyHeight() - 2)
		return m, nil
	}
	if key == "pgup" {
		m.scroll(-m.bodyHeight() + 2)
		return m, nil
	}
	if key == "end" && m.input.Value() == "" {
		m.follow()
		return m, nil
	}
	if key == "home" && m.input.Value() == "" {
		m.offset = 0
		return m, nil
	}
	if m.busy {
		return m, nil
	}
	if key == "enter" {
		text := strings.TrimSpace(m.input.Value())
		if text == "" {
			return m, nil
		}
		m.input.SetValue("")
		if strings.HasPrefix(text, "/") {
			parts := strings.Fields(strings.TrimPrefix(text, "/"))
			return m.runCommand(parts[0], parts[1:])
		}
		m.appendBlock("you", text)
		m.pendingEcho = text
		m.busy = true
		m.send(bridge.ChatMessage{"type": "user_message", "text": text})
		return m, nil
	}
	var cmd tea.Cmd
	old := m.input.Value()
	m.input, cmd = m.input.Update(k)
	if old != m.input.Value() {
		m.menuIndex = 0
	}
	return m, cmd
}

func (m Model) restartCmd() tea.Cmd {
	if m.Restart == nil || m.restarting {
		return nil
	}
	return func() tea.Msg { m.host.Close(); h, err := m.Restart(); return restartedMsg{h, err} }
}
func (m Model) quit() tea.Cmd { return func() tea.Msg { m.host.Close(); return tea.Quit() } }

func (m Model) activate(action string) (tea.Model, tea.Cmd) {
	if action == "restart" {
		if m.disconnected && !m.restarting {
			cmd := m.restartCmd()
			m.restarting = cmd != nil
			return m, cmd
		}
		return m, nil
	}
	if m.disconnected {
		return m, nil
	}
	if m.dialog != nil {
		if strings.HasPrefix(action, "gate:") {
			return m.choose(strings.TrimPrefix(action, "gate:"))
		}
		if action == "dialog:submit" {
			return m.dialogKey(tea.KeyPressMsg{Code: tea.KeyEnter})
		}
		return m, nil
	}
	if m.form != nil {
		return m.formAction(action)
	}
	if m.confirmAuto && action != "auto:yes" && action != "auto:no" {
		return m, nil
	}
	if m.help && action != "help:close" {
		return m, nil
	}
	if strings.HasPrefix(action, "tab:") {
		m.tab, _ = strconv.Atoi(strings.TrimPrefix(action, "tab:"))
		if m.tab == tabBaseline && m.baseline != nil && !m.baselineInit {
			m.baselineInit = true
			return m, m.baseline.Init()
		}
		return m, nil
	}
	if strings.HasPrefix(action, "block:") {
		i, _ := strconv.Atoi(strings.TrimPrefix(action, "block:"))
		if i >= 0 && i < len(m.blocks) {
			m.blocks[i].expanded = !m.blocks[i].expanded
		}
		return m, nil
	}
	if strings.HasPrefix(action, "command:") {
		return m.runCommand(strings.TrimPrefix(action, "command:"), nil)
	}
	if strings.HasPrefix(action, "pending:") {
		parts := strings.SplitN(action, ":", 3)
		if len(parts) == 3 && (!m.busy || parts[1] == "dismiss") {
			m.send(bridge.ChatMessage{"type": "command", "name": "pending", "args": []string{parts[1], parts[2]}})
		}
		return m, nil
	}
	if strings.HasPrefix(action, "baseline:") {
		return m.baselineAction(strings.TrimPrefix(action, "baseline:"))
	}
	switch action {
	case "remote:copy":
		return m, tea.SetClipboard(m.remoteURL)
	case "help":
		m.help = true
	case "help:close":
		m.help = false
	case "auto:yes":
		m.confirmAuto = false
		m.send(bridge.ChatMessage{"type": "command", "name": "mode", "args": []string{"auto", "confirm"}})
	case "auto:no":
		m.confirmAuto = false
	case "send":
		return m.key(tea.KeyPressMsg{Code: tea.KeyEnter})
	default:
		return m.startAction(action)
	}
	return m, nil
}

func textJSON(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }

func (m Model) textInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.disconnected {
		return m, nil
	}
	if m.form != nil {
		return m.updateForm(msg)
	}
	if m.dialog != nil {
		if m.dialog.form != "" {
			var cmd tea.Cmd
			m.dialog.input, cmd = m.dialog.input.Update(msg)
			return m, cmd
		}
		return m, nil
	}
	if m.help || m.confirmAuto {
		return m, nil
	}
	if m.tab == tabBaseline && m.baseline != nil {
		var cmd tea.Cmd
		m.baseline, cmd = m.baseline.Update(msg)
		return m, cmd
	}
	if m.tab != tabChat {
		return m, nil
	}
	if m.screen == startScreen && m.startFocus == 0 {
		var cmd tea.Cmd
		m.target, cmd = m.target.Update(msg)
		return m, cmd
	}
	if m.screen == chatScreen && !m.busy {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}
func prettyJSON(v json.RawMessage) string {
	var value any
	if json.Unmarshal(v, &value) != nil {
		return ""
	}
	return textJSON(value)
}
func (m Model) statusLine() string {
	location := "cloud"
	if m.status.Local {
		location = "local"
	}
	if m.status.Provider == "" {
		return "No session · ask · 0 tokens · $0.0000"
	}
	return fmt.Sprintf("%s:%s · %s · %s · %d tokens · $%.4f", m.status.Provider, m.status.Model, location, m.status.Mode, m.tokens, m.cost)
}
