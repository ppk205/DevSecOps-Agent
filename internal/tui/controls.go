package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/service"
)

const (
	advancedControl = -1
	reviewControl   = -2
	startControl    = -3
	exportControl   = -4
)

var choices = map[int][]string{1: {"fast", "full"}, 7: {"critical", "high", "medium", "low", "info", "none"}, 8: {"no", "yes"}, 9: {"no", "yes"}, 11: {"json", "sarif", "html", "markdown"}}
var actionNames = []string{"New scan", "History", "Activity", "Findings", "Review checkout", "Start reviewed scan", "Retry run", "Export run", "Reports", "Cancel active scan"}

func (m Model) controls() []int {
	if m.tab == 4 {
		return []int{5, 11, exportControl}
	}
	fields := []int{0, 1, advancedControl}
	if m.advanced {
		fields = append(fields, 2, 3, 4, 5, 6, 7, 8, 9, 10)
	}
	return append(fields, reviewControl, startControl)
}
func (m Model) target() string {
	if m.tab == 0 {
		if row := m.historyTable.SelectedRow(); len(row) > 0 {
			return row[0]
		}
		return ""
	}
	return m.selected
}
func (m Model) runLabel(id string) string {
	for _, run := range m.history {
		if service.ID(run.ID) == id {
			return run.RunID
		}
	}
	if id != "" && id == m.activePK {
		return m.active
	}
	if id == "" {
		return "No run selected"
	}
	return "Run " + id
}
func (m *Model) invalidateReview(field int) {
	m.edited[field] = true
	if field == 11 {
		return
	}
	m.reviewGeneration++
	m.reviewed = nil
	m.reviewedCheckout = ""
	m.status = "Settings changed. Ctrl+E reviews the current scan."
}
func (m *Model) clearEvidence() {
	m.evidenceGeneration++
	m.evidenceText, m.evidenceRaw = "", ""
	m.evidenceFocus = false
	m.evidence.SetContent("Select a finding and press Enter.")
}
func (m *Model) activityCmd(id string) tea.Cmd {
	m.activityID = id
	m.activityGeneration++
	if id == "" {
		m.activity.SetContent("Choose a run in History to inspect its retained activity.")
		return nil
	}
	if id == m.activePK {
		m.refreshActivity()
		if !m.scanning {
			return nil
		}
	} else {
		m.savedActivity = service.RunActivity{}
		m.activity.SetContent("Loading activity for " + m.runLabel(id) + "…")
	}
	m.activityLoading = true
	generation, api := m.activityGeneration, m.api
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		activity, err := api.Activity(ctx, id)
		return loaded{kind: "activity", id: id, generation: generation, value: activity, err: err}
	}
}
func (m *Model) refreshActivity() {
	var lines []string
	if m.activityID == m.activePK && (m.scanning || m.activeResult != nil || len(m.log) > 0) {
		label := m.active
		if label == "" {
			label = "New scan · preparing checkout"
		}
		lines = append(lines, "Activity · "+label)
		if m.scanning {
			lines = append(lines, fmt.Sprintf("Running · %.0f seconds · partial evidence is retained", time.Since(m.started).Seconds()))
			if m.savedActivity.RunID != "" {
				lines = append(lines, "Findings retained: "+display(m.savedActivity.Result["findings"]))
			}
		}
		lines = append(lines, "")
		lines = append(lines, m.log...)
		lines = append(lines, "")
		lines = append(lines, resultText(m.activeResult)...)
	} else if m.savedActivity.RunID != "" {
		lines = append(lines, "Saved activity · "+m.savedActivity.RunID, "Status: "+m.savedActivity.Status, "")
		for _, event := range m.savedActivity.Events {
			lines = append(lines, eventText(event))
		}
		lines = append(lines, "")
		lines = append(lines, resultText(m.savedActivity.Result)...)
	} else {
		return
	}
	wasAtBottom := m.activity.AtBottom()
	m.activity.SetContent(strings.Join(lines, "\n"))
	if wasAtBottom {
		m.activity.GotoBottom()
	}
}
func (m *Model) navigate(tab int) tea.Cmd {
	id := m.target()
	m.tab = tab
	m.editing, m.searching, m.keyInput = false, false, false
	m.search.Blur()
	m.keysName.Blur()
	m.keysValue.Blur()
	for i := range m.inputs {
		m.inputs[i].Blur()
	}
	if tab == 1 {
		m.field = 0
	}
	if tab == 4 {
		m.field = 5
	}
	m.resize()
	if tab == 2 {
		if id == "" && m.activePK != "" {
			id = m.activePK
		}
		return m.activityCmd(id)
	}
	if tab == 3 && id != "" {
		if m.selected != id {
			m.selected = id
			m.page.Offset = 0
			m.clearEvidence()
		}
		m.generation++
		return m.findingsCmd()
	}
	return nil
}
func (m *Model) reviewCmd() tea.Cmd {
	values := []string{}
	for _, input := range m.inputs {
		values = append(values, input.Value())
	}
	edited := map[int]bool{}
	for index, value := range m.edited {
		edited[index] = value
	}
	m.reviewed = nil
	m.reviewedCheckout = ""
	m.reviewGeneration++
	generation, signature, api := m.reviewGeneration, m.signature(), m.api
	m.status = "Reviewing checkout…"
	return func() tea.Msg {
		cfg, err := formConfig(values, edited)
		if err != nil {
			return loaded{kind: "review", generation: generation, err: err}
		}
		result, err := api.Review(context.Background(), values[0], cfg)
		return loaded{kind: "review", generation: generation, value: reviewResult{config: cfg, signature: signature, target: values[0], result: result}, err: err}
	}
}
func (m *Model) evidenceCmd() tea.Cmd {
	cursor := m.findingTable.Cursor()
	if cursor < 0 || cursor >= len(m.page.Items) {
		m.status = "No finding selected. Choose a run in History first."
		return nil
	}
	id, fid, api := m.selected, m.page.Items[cursor].FindingID, m.api
	m.clearEvidence()
	m.evidenceFocus = true
	m.evidence.SetContent("Loading finding details…")
	generation := m.evidenceGeneration
	return func() tea.Msg {
		data, err := api.Finding(context.Background(), id, fid)
		var detail findingDetail
		if err == nil {
			detail, err = describeFinding(data)
		}
		return loaded{kind: "evidence", id: id, generation: generation, value: detail, err: err}
	}
}
func (m *Model) changeChoice(delta int) {
	options := choices[m.field]
	if len(options) == 0 {
		return
	}
	index := 0
	for i, value := range options {
		if value == m.inputs[m.field].Value() {
			index = i
		}
	}
	value := options[(index+delta+len(options))%len(options)]
	if value != m.inputs[m.field].Value() {
		m.inputs[m.field].SetValue(value)
		m.invalidateReview(m.field)
	}
}
func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if m.quitModal {
		if key == "esc" || key == "n" {
			m.quitModal = false
		}
		if key == "y" || key == "enter" {
			m.quitModal, m.quitAfter = false, true
			if m.cancelRun != nil {
				m.cancelRun()
			}
		}
		return m, nil
	}
	if key == "ctrl+q" || key == "ctrl+c" {
		if m.scanning {
			m.quitModal = true
			return m, nil
		}
		return m, tea.Quit
	}
	if key == "ctrl+k" {
		if m.tab == 1 || m.keyInput {
			// Save one API key to the project-local .env. Only the variable
			// NAME is ever shown or listed again; the value is passed through
			// once and dropped (EchoPassword on the value field).
			name := strings.TrimSpace(m.keysName.Value())
			if name == "" {
				m.navigate(1)
				m.reviewMode = false
				m.envStatus = "Type a VARIABLE_NAME first."
				m.keyInput = true
				m.keysFocus = 0
				return m, m.keysName.Focus()
			}
			value := m.keysValue.Value()
			m.keysValue.SetValue("")
			m.envStatus = "Saving " + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "…"
			api := m.api
			return m, func() tea.Msg {
				if err := api.EnvSet(context.Background(), name, value); err != nil {
					return loaded{kind: "keys", err: err}
				}
				names, err := api.EnvList(context.Background())
				return loaded{kind: "keys", value: names, err: err}
			}
		}
		// Elsewhere Ctrl+K keeps its newer role: open the action menu (FR71).
		m.menu, m.menuCursor = true, 0
		return m, nil
	}
	if m.menu {
		switch key {
		case "esc":
			m.menu = false
		case "down":
			m.menuCursor = (m.menuCursor + 1) % len(actionNames)
		case "up":
			m.menuCursor = (m.menuCursor + len(actionNames) - 1) % len(actionNames)
		case "enter":
			m.menu = false
			keys := []tea.KeyPressMsg{{Code: 'n', Mod: tea.ModCtrl}, {Code: '1', Mod: tea.ModCtrl}, {Code: '3', Mod: tea.ModCtrl}, {Code: '4', Mod: tea.ModCtrl}, {Code: 'e', Mod: tea.ModCtrl}, {Code: 's', Mod: tea.ModCtrl}, {Code: 't', Mod: tea.ModCtrl}, {Code: 'o', Mod: tea.ModCtrl}, {Code: '5', Mod: tea.ModCtrl}, {Code: 'x', Mod: tea.ModCtrl}}
			return m.handleKey(keys[m.menuCursor])
		}
		return m, nil
	}
	if key == "ctrl+n" {
		m.navigate(1)
		m.reviewMode, m.editing = false, true
		return m, m.inputs[0].Focus()
	}
	if key == "ctrl+r" && m.ready {
		m.navigate(0)
		return m, m.historyCmd()
	}
	if key == "ctrl+x" && m.scanning {
		if m.cancelRun != nil {
			m.cancelRun()
		}
		m.status = "Cancellation requested; partial evidence will be retained."
		return m, nil
	}
	if !m.ready {
		return m.handleInput(msg)
	}
	if len(key) == 6 && strings.HasPrefix(key, "ctrl+") && key[5] >= '1' && key[5] <= '5' {
		return m, m.navigate(int(key[5] - '1'))
	}
	if !m.editing && !m.searching && !m.keyInput && key >= "1" && key <= "5" {
		return m, m.navigate(int(key[0] - '1'))
	}
	if key == "ctrl+e" {
		m.navigate(1)
		return m, m.reviewCmd()
	}
	if key == "ctrl+s" {
		if m.scanning {
			m.status = "A scan is already running. Ctrl+3 opens Activity."
			return m, nil
		}
		if m.reviewed == nil || m.reviewSignature != m.signature() {
			m.status = "Review the current settings with Ctrl+E first."
			return m, nil
		}
		return m, m.begin(false)
	}
	if key == "ctrl+t" {
		id := m.target()
		if id == "" || m.scanning {
			m.status = "Choose a completed run in History; wait for the active scan before retrying."
			return m, nil
		}
		for _, run := range m.history {
			if service.ID(run.ID) == id && (run.Status == "running" || run.Status == "queued") {
				m.status = "This run is active. Ctrl+3 opens its Activity."
				return m, nil
			}
		}
		m.selected = id
		return m, m.begin(true)
	}
	if key == "ctrl+o" {
		id := m.target()
		if id == "" {
			m.status = "Choose a run in History before exporting."
			return m, nil
		}
		format, output, api := m.inputs[11].Value(), m.inputs[5].Value(), m.api
		m.status = "Exporting " + m.runLabel(id) + "…"
		return m, func() tea.Msg {
			path, err := api.Export(context.Background(), id, format, output)
			return loaded{kind: "export", id: id, value: path, err: err}
		}
	}
	if key == "esc" {
		switch {
		case m.keyInput:
			// Leaving key entry keeps whatever is typed; Ctrl+K saves it.
			m.keyInput = false
			m.keysName.Blur()
			m.keysValue.Blur()
		case m.editing:
			m.editing = false
			m.inputs[m.field].Blur()
		case m.searching:
			m.searching = false
			m.search.Blur()
		case m.evidenceFocus:
			m.evidenceFocus = false
		case m.tab == 1 && m.reviewMode:
			m.reviewMode = false
		default:
			m.navigate(1)
		}
		return m, nil
	}
	if m.tab == 0 {
		if key == "enter" {
			id := m.target()
			if id == "" {
				m.status = "No saved runs yet. Ctrl+N configures your first scan."
				return m, nil
			}
			m.selected, m.followActive = id, false
			m.page.Offset = 0
			m.clearEvidence()
			m.generation++
			m.tab = 3
			return m, tea.Batch(m.findingsCmd(), m.activityCmd(id))
		}
		var cmd tea.Cmd
		m.historyTable, cmd = m.historyTable.Update(msg)
		return m, cmd
	}
	if m.tab == 2 {
		var cmd tea.Cmd
		m.activity, cmd = m.activity.Update(msg)
		return m, cmd
	}
	if m.tab == 1 && m.reviewMode {
		if key == "v" {
			m.rawReview = !m.rawReview
			text := m.reviewText
			if m.rawReview {
				text = m.reviewRaw
			}
			m.review.SetContent(text)
			m.review.GotoTop()
			return m, nil
		}
		var cmd tea.Cmd
		m.review, cmd = m.review.Update(msg)
		return m, cmd
	}
	if m.tab == 1 || m.tab == 4 {
		if key == "tab" && m.keyInput {
			// Inside API-key entry: Tab moves name -> value -> name.
			m.keysFocus = (m.keysFocus + 1) % 2
			if m.keysFocus == 0 {
				m.keysValue.Blur()
				return m, m.keysName.Focus()
			}
			m.keysName.Blur()
			return m, m.keysValue.Focus()
		}
		if key == "ctrl+a" && m.tab == 1 && !m.editing {
			m.advanced = !m.advanced
			m.field = advancedControl
			return m, nil
		}
		if key == "ctrl+space" && m.field == 0 {
			value := m.inputs[0].Value()
			return m, func() tea.Msg { return loaded{kind: "completion", id: value, value: completePath(value)} }
		}
		if key == "tab" || key == "shift+tab" {
			if m.field >= 0 {
				m.inputs[m.field].Blur()
			}
			m.editing = false
			controls, index := m.controls(), 0
			for i, field := range controls {
				if field == m.field {
					index = i
				}
			}
			delta := 1
			if key == "shift+tab" {
				delta = -1
			}
			m.field = controls[(index+delta+len(controls))%len(controls)]
			return m, nil
		}
		if key == "enter" {
			switch m.field {
			case advancedControl:
				m.advanced = !m.advanced
			case reviewControl:
				return m, m.reviewCmd()
			case startControl:
				return m.handleKey(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			case exportControl:
				return m.handleKey(tea.KeyPressMsg{Code: 'o', Mod: tea.ModCtrl})
			default:
				if len(choices[m.field]) > 0 {
					m.changeChoice(1)
				} else {
					m.editing = !m.editing
					if m.editing {
						return m, m.inputs[m.field].Focus()
					}
					m.inputs[m.field].Blur()
				}
			}
			return m, nil
		}
		if len(choices[m.field]) > 0 && (key == "left" || key == "right" || key == "space") {
			delta := 1
			if key == "left" {
				delta = -1
			}
			m.changeChoice(delta)
			return m, nil
		}
		return m.handleInput(msg)
	}
	if m.tab == 3 {
		if m.evidenceFocus {
			if key == "tab" {
				m.evidenceFocus = false
				return m, nil
			}
			if key == "v" {
				m.rawEvidence = !m.rawEvidence
				text := m.evidenceText
				if m.rawEvidence {
					text = m.evidenceRaw
				}
				m.evidence.SetContent(text)
				m.evidence.GotoTop()
				return m, nil
			}
			var cmd tea.Cmd
			m.evidence, cmd = m.evidence.Update(msg)
			return m, cmd
		}
		if key == "/" || key == "tab" {
			m.searching = true
			return m, m.search.Focus()
		}
		if key == "enter" {
			if m.searching {
				m.searching = false
				m.search.Blur()
				return m, nil
			}
			return m, m.evidenceCmd()
		}
		if m.searching {
			return m.handleInput(msg)
		}
		if key == "pgdown" || key == "pgup" {
			if key == "pgdown" && m.page.Offset+200 < m.page.Total {
				m.page.Offset += 200
			}
			if key == "pgup" {
				m.page.Offset = max(0, m.page.Offset-200)
			}
			m.clearEvidence()
			m.generation++
			return m, m.findingsCmd()
		}
		var cmd tea.Cmd
		m.findingTable, cmd = m.findingTable.Update(msg)
		return m, cmd
	}
	return m, nil
}
func (m Model) handleInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.keyInput {
		// Typing an API key: name field first, value (hidden) after.
		var cmd tea.Cmd
		if m.keysFocus == 0 {
			m.keysName, cmd = m.keysName.Update(msg)
		} else {
			m.keysValue, cmd = m.keysValue.Update(msg)
		}
		return m, cmd
	}
	if (m.tab == 1 || m.tab == 4) && m.editing && m.field >= 0 && len(choices[m.field]) == 0 {
		old := m.inputs[m.field].Value()
		var cmd tea.Cmd
		m.inputs[m.field], cmd = m.inputs[m.field].Update(msg)
		if old != m.inputs[m.field].Value() {
			m.invalidateReview(m.field)
		}
		return m, cmd
	}
	if m.tab == 3 && m.searching {
		old := m.search.Value()
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		if old != m.search.Value() {
			m.clearEvidence()
			m.searchGeneration++
			m.generation++
			generation := m.searchGeneration
			return m, tea.Batch(cmd, tea.Tick(150*time.Millisecond, func(time.Time) tea.Msg { return searchMsg(generation) }))
		}
		return m, cmd
	}
	return m, nil
}
