package chat

import (
	"encoding/json"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
)

type button struct{ key, choice, label string }

// Keep this literal: tests/harness/test_gates.py checks it against CHOICES.
var buttonTable = map[string][]button{
	"G0": {{"y", "approve", "Approve"}, {"n", "reject", "Reject…"}},
	"G1": {{"y", "approve", "Approve"}, {"e", "edit", "Edit…"}, {"n", "reject", "Reject…"}},
	"G2": {{"y", "approve", "Approve"}, {"e", "edit", "Edit…"}, {"n", "reject", "Reject…"}},
	"G3": {{"y", "approve", "Approve"}, {"e", "edit", "Edit…"}, {"n", "reject", "Reject…"}},
	"G4": {{"y", "approve", "Approve"}, {"e", "edit", "Edit…"}, {"n", "reject", "Reject…"}},
	"G5": {{"c", "confirm", "Confirm"}, {"r", "reject", "Reject…"}, {"m", "need_more", "Need more"}},
	"G6": {{"a", "apply", "Apply"}, {"r", "reject", "Reject…"}, {"d", "defer", "Defer"}},
	"G7": {{"y", "approve", "Approve"}, {"e", "edit", "Edit…"}, {"n", "reject", "Reject…"}},
}

type dialog struct {
	requestID, gate, title, detail, mode, recommendation string
	payload                                              map[string]any
	highlight                                            int
	diffSeenEnd                                          bool
	offset, width, height                                int
	lines                                                []string
	form, err                                            string
	input                                                textinput.Model
	buttons                                              []button
}

func newDialog(raw json.RawMessage) *dialog {
	var req struct {
		RequestID      string         `json:"request_id"`
		Gate           string         `json:"gate"`
		Title          string         `json:"title"`
		Detail         string         `json:"detail"`
		Mode           string         `json:"mode"`
		Recommendation string         `json:"ai_recommendation"`
		Payload        map[string]any `json:"payload"`
		Choices        []string       `json:"choices"`
	}
	_ = json.Unmarshal(raw, &req)
	d := &dialog{requestID: req.RequestID, gate: req.Gate, title: req.Title, detail: req.Detail, mode: req.Mode, recommendation: req.Recommendation, payload: req.Payload, highlight: -1, input: textinput.New()}
	d.input.CharLimit = 1024 * 1024
	for _, b := range buttonTable[d.gate] {
		allowed := len(req.Choices) == 0
		for _, choice := range req.Choices {
			if choice == b.choice {
				allowed = true
			}
		}
		if allowed {
			d.buttons = append(d.buttons, b)
		}
	}
	return d
}
func (m *Model) leaveDialog() {
	if m.dialog != nil {
		m.appendBlock("notice", m.dialog.gate+" left undecided")
		m.dialog = nil
	}
}
func (m Model) choose(choice string) (tea.Model, tea.Cmd) {
	d := m.dialog
	if d == nil || d.form != "" || d.gate == "G6" && !d.diffSeenEnd {
		return m, nil
	}
	allowed := false
	for _, b := range d.buttons {
		if b.choice == choice {
			allowed = true
		}
	}
	if !allowed {
		return m, nil
	}
	if choice == "reject" || choice == "edit" {
		d.form = "reason"
		d.input.SetValue("")
		if choice == "edit" {
			d.form = "edits"
			d.input.SetValue("{}")
		}
		d.err = ""
		d.input.Focus()
		return m, nil
	}
	m.send(bridge.ChatMessage{"type": "permission_reply", "request_id": d.requestID, "choice": choice, "reason": "", "edits": map[string]any{}})
	if !m.disconnected {
		m.dialog = nil
	}
	return m, nil
}
func (m Model) dialogKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	d := m.dialog
	key := k.String()
	if d.form != "" {
		if key == "esc" {
			d.form = ""
			d.err = ""
			d.input.SetValue("")
			d.highlight = -1
			return m, nil
		}
		if key == "enter" {
			choice, reason := "reject", strings.TrimSpace(d.input.Value())
			edits := map[string]any{}
			if d.form == "edits" {
				if json.Unmarshal([]byte(d.input.Value()), &edits) != nil || edits == nil {
					d.err = "Edits must be a JSON object."
					return m, nil
				}
				choice = "edit"
				reason = ""
			} else if reason == "" {
				d.err = "Enter a rejection reason."
				return m, nil
			}
			m.send(bridge.ChatMessage{"type": "permission_reply", "request_id": d.requestID, "choice": choice, "reason": reason, "edits": edits})
			if !m.disconnected {
				m.dialog = nil
			}
			return m, nil
		}
		var cmd tea.Cmd
		d.input, cmd = d.input.Update(k)
		return m, cmd
	}
	switch key {
	case "esc":
		m.leaveDialog()
	case "right", "tab":
		if len(d.buttons) > 0 {
			d.highlight = (d.highlight + 1) % len(d.buttons)
		}
	case "left", "shift+tab":
		if len(d.buttons) > 0 {
			if d.highlight < 0 {
				d.highlight = len(d.buttons) - 1
			} else {
				d.highlight = (d.highlight - 1 + len(d.buttons)) % len(d.buttons)
			}
		}
	case "enter":
		if d.highlight >= 0 {
			return m.choose(d.buttons[d.highlight].choice)
		}
	case "down":
		d.scroll(1)
	case "up":
		d.scroll(-1)
	case "pgdown", "ctrl+d":
		d.scroll(d.height)
	case "pgup", "ctrl+u":
		d.scroll(-d.height)
	case "end":
		d.scroll(len(d.lines))
	case "home":
		d.scroll(-len(d.lines))
	default:
		for _, b := range d.buttons {
			if key == b.key {
				return m.choose(b.choice)
			}
		}
	}
	return m, nil
}
