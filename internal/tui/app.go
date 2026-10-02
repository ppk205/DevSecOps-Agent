// Package tui implements the responsive terminal workspace (FR-71, QR-21).
package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"devsecops-agent/internal/bridge"
	"devsecops-agent/internal/service"
)

type API interface {
	Init(context.Context) error
	History(context.Context) ([]service.RunSummary, error)
	Findings(context.Context, string, string, int) (service.FindingPage, error)
	Finding(context.Context, string, string) (json.RawMessage, error)
	Review(context.Context, string, service.Config) (map[string]any, error)
	Run(context.Context, map[string]any, func(bridge.Event)) (map[string]any, error)
	Retry(context.Context, string, func(bridge.Event)) (map[string]any, error)
	Cancel(context.Context, string) error
	Export(context.Context, string, string, string) (string, error)
	Capabilities(context.Context) ([]map[string]any, error)
}
type loaded struct {
	kind       string
	generation uint64
	id         string
	value      any
	err        error
}
type tickMsg time.Time
type searchMsg uint64
type progressMsg bridge.Event
type finishedMsg struct {
	result map[string]any
	err    error
}
type reviewResult struct {
	config    service.Config
	signature string
	result    map[string]any
}
type Model struct {
	api                API
	Send               func(tea.Msg)
	width, height      int
	ready              bool
	tab                int
	field              int
	inputs             []textinput.Model
	search             textinput.Model
	searching          bool
	history            []service.RunSummary
	historyTable       table.Model
	findingTable       table.Model
	page               service.FindingPage
	selected           string
	active             string
	activePK           string
	scanning           bool
	started            time.Time
	quitModal          bool
	quitAfter          bool
	cancelRun          context.CancelFunc
	generation         uint64
	evidenceGeneration uint64
	searchGeneration   uint64
	reviewGeneration   uint64
	historyGeneration  uint64
	edited             map[int]bool
	reviewSignature    string
	reviewed           *service.Config
	dirty              bool
	status             string
	availability       string
	log                []string
	evidence           viewport.Model
	review             viewport.Model
}

var labels = []string{"Checkout", "Profile (fast/full)", "Configuration file", "Timeout (seconds)", "Maximum files", "Artifact directory", "Timezone", "Threshold", "Allow dirty (yes/no)", "Laya (yes/no)", "Laya configuration file", "Export format"}
var tabs = []string{"Overview", "Setup", "Progress", "Findings", "Settings"}

func New(api API) Model {
	m := Model{api: api, width: 100, height: 35, status: "Loading scan workspace…", availability: "Checking scanner availability…", edited: make(map[int]bool)}
	defaults := []string{".", "fast", "", "600", "100000", "artifacts", "Asia/Saigon", "high", "no", "no", "", "json"}
	for _, value := range defaults {
		input := textinput.New()
		input.SetValue(value)
		input.CharLimit = 2048
		input.SetWidth(60)
		m.inputs = append(m.inputs, input)
	}
	m.search = textinput.New()
	m.search.Placeholder = "Search or severity:high cwe:89 scanner:semgrep"
	m.search.SetWidth(70)
	m.historyTable = table.New(table.WithColumns([]table.Column{{Title: "ID", Width: 6}, {Title: "Run", Width: 24}, {Title: "Status", Width: 15}, {Title: "Attempt", Width: 7}, {Title: "Started", Width: 22}}), table.WithFocused(true), table.WithHeight(12))
	m.findingTable = table.New(table.WithColumns([]table.Column{{Title: "Severity", Width: 12}, {Title: "CWE", Width: 16}, {Title: "Status", Width: 15}, {Title: "Scanner", Width: 20}, {Title: "Title", Width: 40}}), table.WithFocused(true), table.WithHeight(10))
	m.evidence = viewport.New(viewport.WithWidth(96), viewport.WithHeight(8))
	m.evidence.SetContent("Select a finding and press Enter to inspect evidence.")
	m.review = viewport.New(viewport.WithWidth(96), viewport.WithHeight(10))
	m.review.SetContent("Press Ctrl+E to review effective settings, then Ctrl+S to start.")
	return m
}
func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}
func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(), func() tea.Msg { return loaded{kind: "init", err: m.api.Init(context.Background())} })
}
func (m *Model) historyCmd() tea.Cmd {
	m.historyGeneration++
	generation := m.historyGeneration
	return func() tea.Msg {
		rows, err := m.api.History(context.Background())
		return loaded{kind: "history", generation: generation, value: rows, err: err}
	}
}
func (m Model) findingsCmd() tea.Cmd {
	id, query, offset, generation := m.selected, m.search.Value(), m.page.Offset, m.generation
	return func() tea.Msg {
		page, err := m.api.Findings(context.Background(), id, query, offset)
		return loaded{kind: "findings", id: id, generation: generation, value: page, err: err}
	}
}
func (m Model) signature() string {
	values := []string{}
	for _, input := range m.inputs {
		values = append(values, input.Value())
	}
	data, _ := json.Marshal(values)
	return string(data)
}
func (m Model) config() (service.Config, error) {
	values := make([]string, len(m.inputs))
	for i, input := range m.inputs {
		values[i] = input.Value()
	}
	return formConfig(values, m.edited)
}
func formConfig(values []string, edited map[int]bool) (service.Config, error) {
	flags := map[string]any{}
	defaults := service.Defaults()
	if values[3] != "600" || edited[3] {
		v, err := strconv.Atoi(values[3])
		if err != nil {
			return defaults, err
		}
		flags["timeout"] = v
	}
	if values[4] != "100000" || edited[4] {
		v, err := strconv.Atoi(values[4])
		if err != nil {
			return defaults, err
		}
		flags["max_files"] = v
	}
	for index, name := range map[int]string{5: "output_dir", 6: "timezone", 7: "fail_on"} {
		if values[index] != []string{"artifacts", "Asia/Saigon", "high"}[index-5] || edited[index] {
			flags[name] = values[index]
		}
	}
	for index, name := range map[int]string{8: "allow_dirty", 9: "laya"} {
		value := strings.ToLower(values[index])
		if value != "yes" && value != "no" {
			return defaults, fmt.Errorf("%s must be yes or no", name)
		}
		if value == "yes" || edited[index] {
			flags[name] = value == "yes"
		}
	}
	if values[10] != "" {
		flags["laya_config_path"] = values[10]
	}
	return service.Resolve(values[1], values[2], flags)
}
func (m *Model) begin(retry bool) tea.Cmd {
	m.scanning = true
	m.active = ""
	m.activePK = ""
	m.started = time.Now()
	m.log = nil
	m.tab = 2
	m.status = "Starting scan…"
	m.quitAfter = false
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelRun = cancel
	api, send, id := m.api, m.Send, m.selected
	config, checkout := m.reviewed, m.inputs[0].Value()
	return func() tea.Msg {
		progress := func(e bridge.Event) {
			if send != nil {
				send(progressMsg(e))
			}
		}
		var result map[string]any
		var err error
		if retry {
			result, err = api.Retry(ctx, id, progress)
		} else {
			result, err = api.Run(ctx, map[string]any{"checkout": checkout, "configuration": config}, progress)
		}
		return finishedMsg{result, err}
	}
}
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.historyTable.SetHeight(max(3, msg.Height-10))
		m.findingTable.SetHeight(max(3, (msg.Height-12)/2))
		m.evidence.SetWidth(max(10, msg.Width-4))
		m.evidence.SetHeight(max(3, (msg.Height-12)/2))
		m.review.SetWidth(max(10, msg.Width-4))
		m.review.SetHeight(max(3, msg.Height-24))
		m.historyTable.SetWidth(max(10, msg.Width-4))
		m.findingTable.SetWidth(max(10, msg.Width-4))
		m.findingTable.SetColumns([]table.Column{{Title: "Severity", Width: 9}, {Title: "CWE", Width: 10}, {Title: "Status", Width: 12}, {Title: "Scanner", Width: 14}, {Title: "Title", Width: max(10, msg.Width-59)}})
		m.historyTable.SetColumns([]table.Column{{Title: "ID", Width: 5}, {Title: "Run", Width: max(10, msg.Width-62)}, {Title: "Status", Width: 14}, {Title: "Attempt", Width: 7}, {Title: "Started", Width: 22}})
		m.search.SetWidth(max(10, msg.Width-8))
		for i := range m.inputs {
			m.inputs[i].SetWidth(max(10, msg.Width-8))
		}
	case loaded:
		if msg.kind == "review" && msg.generation != m.reviewGeneration || msg.kind == "findings" && (msg.generation != m.generation || msg.id != m.selected) || msg.kind == "history" && msg.generation != m.historyGeneration {
			break
		}
		if msg.err != nil {
			m.status = msg.err.Error()
			break
		}
		switch msg.kind {
		case "init":
			m.ready = true
			m.status = "Ready"
			cmds = append(cmds, m.historyCmd(), func() tea.Msg {
				caps, err := m.api.Capabilities(context.Background())
				return loaded{kind: "capabilities", value: caps, err: err}
			})
		case "history":
			old := m.historyTable.SelectedRow()
			m.history = msg.value.([]service.RunSummary)
			rows := []table.Row{}
			restore := 0
			for i, r := range m.history {
				zone, err := time.LoadLocation(m.inputs[6].Value())
				if err != nil {
					zone, _ = time.LoadLocation("Asia/Saigon")
				}
				stamp := r.CreatedAt
				if parsed, err := time.Parse(time.RFC3339Nano, r.CreatedAt); err == nil {
					stamp = parsed.In(zone).Format("2006-01-02 15:04 -0700")
				}
				rows = append(rows, table.Row{strconv.Itoa(r.ID), r.RunID, r.Status, strconv.Itoa(r.Attempt), stamp})
				if len(old) > 0 && old[0] == strconv.Itoa(r.ID) {
					restore = i
				}
			}
			m.historyTable.SetRows(rows)
			m.historyTable.SetCursor(restore)
		case "capabilities":
			parts := []string{}
			for _, cap := range msg.value.([]map[string]any) {
				state := "unavailable"
				if cap["available"] == true {
					state = "available"
				}
				parts = append(parts, fmt.Sprintf("%v: %s", cap["tool"], state))
			}
			m.availability = strings.Join(parts, " | ")
		case "findings":
			if msg.generation != m.generation || msg.id != m.selected {
				break
			}
			page := msg.value.(service.FindingPage)
			if page.Offset >= page.Total && page.Offset > 0 {
				m.page.Offset = max(0, (page.Total-1)/200*200)
				m.generation++
				cmds = append(cmds, m.findingsCmd())
				break
			}
			old := m.findingTable.Cursor()
			key := ""
			if old >= 0 && old < len(m.page.Items) {
				key = m.page.Items[old].FindingID
			}
			rows := []table.Row{}
			restore := min(old, max(0, len(page.Items)-1))
			for i, r := range page.Items {
				rows = append(rows, table.Row{r.Severity, r.CWE, r.Status, r.Scanner, r.Title})
				if r.FindingID == key {
					restore = i
				}
			}
			m.page = page
			m.findingTable.SetRows(rows)
			m.findingTable.SetCursor(restore)
		case "evidence":
			if msg.generation == m.evidenceGeneration && msg.id == m.selected {
				m.evidence.SetContent(msg.value.(string))
				m.evidence.GotoTop()
			}
		case "review":
			if msg.generation == m.reviewGeneration {
				result := msg.value.(reviewResult)
				data, _ := json.MarshalIndent(result.result, "", "  ")
				m.review.SetContent(string(data))
				m.reviewSignature = result.signature
				m.reviewed = &result.config
				m.status = "Settings reviewed. Ctrl+S starts this scan."
			}
		case "export":
			m.status = "Exported: " + msg.value.(string)
		case "cancel":
			m.status = "Cancellation requested; preserving partial evidence…"
		}
	case searchMsg:
		if uint64(msg) == m.searchGeneration && m.selected != "" {
			m.page.Offset = 0
			m.generation++
			cmds = append(cmds, m.findingsCmd())
		}
	case progressMsg:
		e := bridge.Event(msg)
		if m.active == "" {
			m.active = e.RunID
			m.activePK = service.ID(e.PK)
			m.selected = m.activePK
			m.page.Offset = 0
			m.generation++
		}
		m.log = append(m.log, fmt.Sprintf("%s: %s %s", e.Stage, e.Status, e.Message))
		if len(m.log) > 200 {
			m.log = m.log[len(m.log)-200:]
		}
		m.dirty = true
	case finishedMsg:
		m.scanning = false
		m.cancelRun = nil
		if msg.err != nil {
			m.status = msg.err.Error()
		} else {
			m.status = fmt.Sprintf("%v: %v | gate %v | exit %v", msg.result["run_id"], msg.result["status"], msg.result["gate"], msg.result["exit_code"])
		}
		cmds = append(cmds, m.historyCmd())
		if m.selected == m.activePK {
			m.generation++
			cmds = append(cmds, m.findingsCmd())
		}
		if m.quitAfter {
			return m, tea.Quit
		}
	case tickMsg:
		cmds = append(cmds, tick())
		if m.ready && m.tab == 3 && m.dirty && m.selected == m.activePK {
			m.dirty = false
			m.generation++
			cmds = append(cmds, m.findingsCmd())
		}
	case tea.KeyPressMsg:
		key := msg.String()
		if m.quitModal {
			if key == "esc" || key == "n" {
				m.quitModal = false
			}
			if key == "y" || key == "enter" {
				m.quitModal = false
				m.quitAfter = true
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
		if key == "ctrl+n" {
			m.tab = 1
			m.field = 0
			m.inputs[0].Focus()
			return m, nil
		}
		if key == "ctrl+r" && m.ready {
			m.tab = 0
			return m, m.historyCmd()
		}
		if key == "ctrl+x" && m.scanning {
			if m.cancelRun != nil {
				m.cancelRun()
			}
			m.status = "Cancellation requested…"
			return m, nil
		}
		if !m.ready {
			break
		}
		if key == "ctrl+e" && m.tab == 1 {
			values := make([]string, len(m.inputs))
			for i, input := range m.inputs {
				values[i] = input.Value()
			}
			edited := make(map[int]bool)
			for i, value := range m.edited {
				edited[i] = value
			}
			signature := m.signature()
			m.reviewed = nil
			m.reviewGeneration++
			generation := m.reviewGeneration
			checkout := values[0]
			m.status = "Reviewing checkout…"
			cmds = append(cmds, func() tea.Msg {
				cfg, err := formConfig(values, edited)
				if err != nil {
					return loaded{kind: "review", generation: generation, err: err}
				}
				result, err := m.api.Review(context.Background(), checkout, cfg)
				return loaded{kind: "review", generation: generation, value: reviewResult{cfg, signature, result}, err: err}
			})
			break
		}
		if key == "ctrl+s" && !m.scanning && m.tab == 1 {
			if m.reviewed == nil || m.reviewSignature != m.signature() {
				m.status = "Review the current settings with Ctrl+E first"
				break
			}
			return m, m.begin(false)
		}
		if key == "ctrl+t" && !m.scanning && m.selected != "" {
			return m, m.begin(true)
		}
		if key == "ctrl+o" && m.selected != "" {
			id, format, output := m.selected, m.inputs[11].Value(), m.inputs[5].Value()
			cmds = append(cmds, func() tea.Msg {
				path, err := m.api.Export(context.Background(), id, format, output)
				return loaded{kind: "export", value: path, err: err}
			})
			break
		}
		if key == "esc" {
			m.searching = false
			m.search.Blur()
			for i := range m.inputs {
				m.inputs[i].Blur()
			}
			m.tab = 0
			break
		}
		if key == "tab" || key == "shift+tab" {
			if m.tab == 1 || m.tab == 4 {
				m.inputs[m.field].Blur()
				delta := 1
				if key == "shift+tab" {
					delta = -1
				}
				start, end := 0, 5
				if m.tab == 4 {
					start, end = 5, len(m.inputs)
				}
				m.field = start + (m.field-start+delta+end-start)%(end-start)
				cmds = append(cmds, m.inputs[m.field].Focus())
			} else {
				m.tab = (m.tab + 1) % len(tabs)
				if m.tab == 1 {
					m.field = 0
					cmds = append(cmds, m.inputs[0].Focus())
				}
				if m.tab == 4 {
					m.field = 5
					cmds = append(cmds, m.inputs[5].Focus())
				}
			}
			break
		}
		if m.tab != 1 && m.tab != 4 && !m.searching && key >= "1" && key <= "5" {
			m.tab = int(key[0] - '1')
			if m.tab == 1 {
				m.field = 0
				cmds = append(cmds, m.inputs[0].Focus())
			}
			if m.tab == 4 {
				m.field = 5
				cmds = append(cmds, m.inputs[5].Focus())
			}
			break
		}
		if m.tab == 0 && key == "enter" {
			row := m.historyTable.SelectedRow()
			if len(row) > 0 {
				m.selected = row[0]
				m.page.Offset = 0
				m.evidenceGeneration++
				m.evidence.SetContent("Select a finding and press Enter.")
				m.generation++
				m.tab = 3
				cmds = append(cmds, m.findingsCmd())
			}
			break
		}
		if m.tab == 3 && key == "/" && !m.searching {
			m.searching = true
			cmds = append(cmds, m.search.Focus())
			break
		}
		if m.tab == 3 && key == "enter" {
			if m.searching {
				m.searching = false
				m.search.Blur()
				break
			}
			cursor := m.findingTable.Cursor()
			if cursor >= 0 && cursor < len(m.page.Items) {
				id, fid := m.selected, m.page.Items[cursor].FindingID
				m.evidenceGeneration++
				generation := m.evidenceGeneration
				cmds = append(cmds, func() tea.Msg {
					data, err := m.api.Finding(context.Background(), id, fid)
					var formatted json.RawMessage
					if err == nil {
						formatted = data
					}
					var object any
					_ = json.Unmarshal(formatted, &object)
					var text bytes.Buffer
					encoder := json.NewEncoder(&text)
					encoder.SetEscapeHTML(false)
					encoder.SetIndent("", "  ")
					_ = encoder.Encode(object)
					return loaded{kind: "evidence", id: id, generation: generation, value: text.String(), err: err}
				})
			}
			break
		}
		if m.tab == 3 && !m.searching && (key == "pgdown" || key == "pgup") {
			offset := m.page.Offset
			if key == "pgdown" && offset+200 < m.page.Total {
				offset += 200
			}
			if key == "pgup" {
				offset = max(0, offset-200)
			}
			m.page.Offset = offset
			m.generation++
			cmds = append(cmds, m.findingsCmd())
			break
		}
		if m.tab == 3 && m.searching {
			old := m.search.Value()
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
			cmds = append(cmds, cmd)
			if old != m.search.Value() {
				m.searchGeneration++
				m.generation++
				generation := m.searchGeneration
				cmds = append(cmds, tea.Tick(150*time.Millisecond, func(time.Time) tea.Msg { return searchMsg(generation) }))
			}
			break
		}
		if m.tab == 1 || m.tab == 4 {
			old := m.inputs[m.field].Value()
			var cmd tea.Cmd
			m.inputs[m.field], cmd = m.inputs[m.field].Update(msg)
			m.reviewGeneration++
			if old != m.inputs[m.field].Value() {
				m.edited[m.field] = true
			}
			cmds = append(cmds, cmd)
			break
		}
		if m.tab == 0 {
			var cmd tea.Cmd
			m.historyTable, cmd = m.historyTable.Update(msg)
			cmds = append(cmds, cmd)
		}
		if m.tab == 3 {
			var cmd tea.Cmd
			if strings.HasPrefix(key, "ctrl+") {
				m.evidence, cmd = m.evidence.Update(msg)
			} else {
				m.findingTable, cmd = m.findingTable.Update(msg)
			}
			cmds = append(cmds, cmd)
		}
	default:
		// Clipboard and cursor messages arrive independently of key presses.
		if m.tab == 1 || m.tab == 4 {
			old := m.inputs[m.field].Value()
			var cmd tea.Cmd
			m.inputs[m.field], cmd = m.inputs[m.field].Update(msg)
			cmds = append(cmds, cmd)
			if old != m.inputs[m.field].Value() {
				m.edited[m.field] = true
				m.reviewGeneration++
			}
		}
		if m.tab == 3 && m.searching {
			old := m.search.Value()
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
			cmds = append(cmds, cmd)
			if old != m.search.Value() {
				m.searchGeneration++
				m.generation++
				generation := m.searchGeneration
				cmds = append(cmds, tea.Tick(150*time.Millisecond, func(time.Time) tea.Msg { return searchMsg(generation) }))
			}
		}
	}
	return m, tea.Batch(cmds...)
}
func (m Model) View() tea.View {
	if m.quitModal {
		v := tea.NewView("A scan is active. Cancel it and preserve partial evidence before quitting?\n\nY/Enter: cancel and quit    N/Esc: stay")
		v.AltScreen = true
		return v
	}
	header := []string{}
	for i, name := range tabs {
		if i == m.tab {
			name = lipgloss.NewStyle().Bold(true).Underline(true).Render(name)
		}
		header = append(header, fmt.Sprintf("%d %s", i+1, name))
	}
	content := ""
	switch m.tab {
	case 0:
		content = m.availability + "\n\n" + m.historyTable.View() + "\nEnter: inspect selected run    Ctrl+T: retry"
	case 1, 4:
		start, end := 0, 5
		if m.tab == 4 {
			start, end = 5, len(m.inputs)
		}
		for i := start; i < end; i++ {
			marker := "  "
			if i == m.field {
				marker = "> "
			}
			content += marker + labels[i] + "\n  " + m.inputs[i].View() + "\n"
		}
		if m.tab == 1 {
			content += "\nCtrl+E: review    Ctrl+S: start    Tab: next field\n" + m.review.View()
		} else {
			content += "\nCtrl+O: export selected run"
		}
	case 2:
		if m.scanning {
			content = fmt.Sprintf("Running %s · %.0fs\n", m.active, time.Since(m.started).Seconds())
		}
		start := max(0, len(m.log)-max(1, m.height-10))
		content += strings.Join(m.log[start:], "\n")
	case 3:
		content = "Run: " + m.selected + "\n" + m.search.View() + "\n" + m.findingTable.View() + fmt.Sprintf("\n%d–%d of %d · /: search · PgUp/PgDown: pages · Enter: evidence\n", min(m.page.Offset+1, m.page.Total), min(m.page.Offset+200, m.page.Total), m.page.Total) + m.evidence.View()
	}
	text := "DevSecOps Agent · Go terminal\n" + strings.Join(header, " | ") + "\n\n" + content + "\n\n" + m.status + "\nCtrl+N new scan · Ctrl+R history · Ctrl+X cancel · Ctrl+Q quit · Esc overview"
	v := tea.NewView(text)
	v.AltScreen = true
	return v
}
