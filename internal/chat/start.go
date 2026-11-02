package chat

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
)

type modelEntry struct {
	Alias        string   `json:"alias"`
	Protocol     string   `json:"protocol"`
	BaseURL      string   `json:"base_url"`
	Models       []string `json:"models"`
	DefaultModel string   `json:"default_model"`
	Local        bool     `json:"local"`
	KeySet       bool     `json:"key_set"`
}
type templateEntry struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Protocol     string   `json:"protocol"`
	BaseURL      string   `json:"base_url"`
	Models       []string `json:"models"`
	DefaultModel string   `json:"default_model"`
}

type modelForm struct {
	kind, alias, err string
	fields           []textinput.Model
	focus, template  int
}

func (m Model) selectedModel() *modelEntry {
	if len(m.models) == 0 {
		return nil
	}
	return &m.models[min(m.modelIndex, len(m.models)-1)]
}
func (m Model) modelSpec() string {
	entry := m.selectedModel()
	if entry == nil {
		return ""
	}
	id := entry.DefaultModel
	if len(entry.Models) > 0 {
		id = entry.Models[min(m.modelIDIndex, len(entry.Models)-1)]
	}
	if id == "" {
		return entry.Alias
	}
	return entry.Alias + ":" + id
}
func (m Model) startReason() string {
	if m.starting {
		return "Starting session…"
	}
	if strings.TrimSpace(m.target.Value()) == "" {
		return "Enter a target path."
	}
	entry := m.selectedModel()
	if entry == nil {
		return "Add a model first."
	}
	if !entry.Local && !entry.KeySet {
		return "Set the key for this model."
	}
	return ""
}
func modelLabel(entry modelEntry) string {
	location, key := "cloud", "missing"
	if entry.Local {
		location = "local"
	}
	if entry.KeySet {
		key = "set"
	}
	return fmt.Sprintf("%s · key %s · %s", entry.Alias, key, location)
}
func newModelForm(kind, alias string) *modelForm {
	f := &modelForm{kind: kind, alias: alias}
	values := []string{"", "Custom", "openai_compatible", "", "", ""}
	if kind == "key" {
		values = []string{""}
	}
	for i, value := range values {
		input := textinput.New()
		input.CharLimit = 4096
		input.SetWidth(60)
		input.SetValue(value)
		if i == len(values)-1 {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		f.fields = append(f.fields, input)
	}
	f.fields[0].Focus()
	return f
}
func (m Model) startAction(action string) (tea.Model, tea.Cmd) {
	switch {
	case action == "model:add":
		m.form = newModelForm("add", "")
		m.resize()
	case strings.HasPrefix(action, "key:"):
		m.form = newModelForm("key", strings.TrimPrefix(action, "key:"))
		m.resize()
	case strings.HasPrefix(action, "remove:"):
		m.send(bridge.ChatMessage{"type": "model_remove", "alias": strings.TrimPrefix(action, "remove:")})
	case action == "start":
		if reason := m.startReason(); reason != "" {
			m.notice = reason
			return m, nil
		}
		m.starting = true
		m.send(bridge.ChatMessage{"type": "start", "target": strings.TrimSpace(m.target.Value()), "model": m.modelSpec(), "mode": m.startMode})
	case action == "start:target":
		m.startFocus = 0
		m.target.Focus()
	case action == "start:model":
		m.startFocus = 1
		m.cycleModel(1)
	case action == "start:mode":
		m.startFocus = 2
		if m.startMode == "ask" {
			m.startMode = "auto"
		} else {
			m.startMode = "ask"
		}
	}
	return m, nil
}
func (m *Model) cycleModel(delta int) {
	var options [][2]int
	for i, entry := range m.models {
		for j := 0; j < max(1, len(entry.Models)); j++ {
			options = append(options, [2]int{i, j})
		}
	}
	if len(options) == 0 {
		return
	}
	at := 0
	for i, p := range options {
		if p == [2]int{m.modelIndex, m.modelIDIndex} {
			at = i
		}
	}
	at = (at + delta + len(options)) % len(options)
	m.modelIndex, m.modelIDIndex = options[at][0], options[at][1]
}
func (m Model) startKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if key == "tab" || key == "shift+tab" {
		delta := 1
		if key == "shift+tab" {
			delta = -1
		}
		count := 5 + 2*len(m.pending)
		m.startFocus = (m.startFocus + delta + count) % count
		m.target.Blur()
		if m.startFocus == 0 {
			m.target.Focus()
		}
		return m, nil
	}
	if (key == "right" || key == "left") && m.startFocus == 1 {
		delta := 1
		if key == "left" {
			delta = -1
		}
		m.cycleModel(delta)
		return m, nil
	}
	if m.startFocus == 2 && (key == "right" || key == "left" || key == "enter") {
		return m.startAction("start:mode")
	}
	if key == "enter" {
		if m.startFocus >= 5 {
			i := (m.startFocus - 5) / 2
			if i < len(m.pending) {
				action := "review"
				if (m.startFocus-5)%2 == 1 {
					action = "dismiss"
				}
				return m.activate("pending:" + action + ":" + m.pending[i].ID)
			}
			return m, nil
		}
		switch m.startFocus {
		case 0:
			m.startFocus = 1
			m.target.Blur()
		case 1:
			m.startFocus = 2
		case 3:
			return m.startAction("model:add")
		case 4:
			return m.startAction("start")
		}
		return m, nil
	}
	if m.startFocus == 0 {
		var cmd tea.Cmd
		m.target, cmd = m.target.Update(k)
		return m, cmd
	}
	return m, nil
}
func (m Model) keysKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "a":
		return m.startAction("model:add")
	case "up":
		m.keysIndex = max(0, m.keysIndex-1)
	case "down":
		m.keysIndex = min(max(0, len(m.models)-1), m.keysIndex+1)
	case "left", "right", "tab":
		m.keysAction = 1 - m.keysAction
	case "enter":
		if len(m.models) > 0 {
			prefix := "key:"
			if m.keysAction == 1 {
				prefix = "remove:"
			}
			return m.startAction(prefix + m.models[m.keysIndex].Alias)
		}
	}
	return m, nil
}
func (m Model) formAction(action string) (tea.Model, tea.Cmd) {
	if action == "form:cancel" {
		m.form = nil
		return m, nil
	}
	if action == "form:submit" {
		return m.submitForm()
	}
	var i int
	if _, err := fmt.Sscanf(action, "form:field:%d", &i); err == nil && i >= 0 && i < len(m.form.fields) {
		m.form.focus = i
		if m.form.kind == "add" && i == 1 {
			m.cycleTemplate(1)
		}
		return m.focusForm()
	}
	return m, nil
}
func (m Model) focusForm() (tea.Model, tea.Cmd) {
	for i := range m.form.fields {
		m.form.fields[i].Blur()
	}
	if m.form.focus < len(m.form.fields) {
		return m, m.form.fields[m.form.focus].Focus()
	}
	return m, nil
}
func (m Model) formKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	f := m.form
	key := k.String()
	if key == "esc" {
		m.form = nil
		return m, nil
	}
	if key == "tab" || key == "shift+tab" {
		delta := 1
		if key == "shift+tab" {
			delta = -1
		}
		f.focus = (f.focus + delta + len(f.fields) + 1) % (len(f.fields) + 1)
		return m.focusForm()
	}
	if key == "enter" {
		if f.kind == "key" || f.focus == len(f.fields) {
			return m.submitForm()
		}
		f.focus++
		return m.focusForm()
	}
	if f.kind == "add" && f.focus == 1 && (key == "left" || key == "right" || key == "down" || key == "up") {
		delta := 1
		if key == "left" || key == "up" {
			delta = -1
		}
		m.cycleTemplate(delta)
		return m, nil
	}
	return m.updateForm(k)
}

func (m *Model) cycleTemplate(delta int) {
	f := m.form
	f.template = (f.template + delta + len(m.templates) + 1) % (len(m.templates) + 1)
	if f.template == 0 {
		f.fields[1].SetValue("Custom")
		return
	}
	entry := m.templates[f.template-1]
	label := entry.Label
	if label == "" {
		label = entry.ID
	}
	f.fields[1].SetValue(label)
	f.fields[2].SetValue(entry.Protocol)
	f.fields[3].SetValue(entry.BaseURL)
	ids := entry.Models
	if len(ids) == 0 && entry.DefaultModel != "" {
		ids = []string{entry.DefaultModel}
	}
	f.fields[4].SetValue(strings.Join(ids, ","))
}
func (m Model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.form.focus >= len(m.form.fields) {
		return m, nil
	}
	if m.form.kind == "add" && m.form.focus == 1 {
		return m, nil
	}
	var cmd tea.Cmd
	m.form.fields[m.form.focus], cmd = m.form.fields[m.form.focus].Update(msg)
	return m, cmd
}
func (m Model) submitForm() (tea.Model, tea.Cmd) {
	f := m.form
	if f.kind == "key" {
		if f.fields[0].Value() == "" {
			f.err = "Enter the key."
			return m, nil
		}
		m.send(bridge.ChatMessage{"type": "model_key", "alias": f.alias, "key": f.fields[0].Value()})
	} else {
		for _, i := range []int{0, 2, 3, 4} {
			if strings.TrimSpace(f.fields[i].Value()) == "" {
				f.err = "Name, protocol, base URL and model ids are required."
				return m, nil
			}
		}
		ids := strings.FieldsFunc(f.fields[4].Value(), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })
		var template any
		if f.template > 0 && f.template <= len(m.templates) {
			template = m.templates[f.template-1].ID
		}
		// protocol is reserved for the devsec-chat/1 envelope.
		m.send(bridge.ChatMessage{"type": "model_add", "alias": f.fields[0].Value(), "template": template, "model_protocol": f.fields[2].Value(), "base_url": f.fields[3].Value(), "models": ids, "key": f.fields[5].Value()})
	}
	for i := range f.fields {
		f.fields[i].SetValue("")
	}
	m.form = nil
	return m, nil
}
