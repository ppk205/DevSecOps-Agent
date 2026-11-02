// Package tui implements the responsive terminal workspace (FR-71, QR-21).
package tui

import (
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
	"devsecops-agent/internal/bridge"
	"devsecops-agent/internal/service"
)

type API interface {
	Init(context.Context) error
	History(context.Context) ([]service.RunSummary, error)
	Activity(context.Context, string) (service.RunActivity, error)
	Findings(context.Context, string, string, int) (service.FindingPage, error)
	Finding(context.Context, string, string) (json.RawMessage, error)
	Review(context.Context, string, service.Config) (map[string]any, error)
	Run(context.Context, map[string]any, func(bridge.Event)) (map[string]any, error)
	Retry(context.Context, string, func(bridge.Event)) (map[string]any, error)
	Cancel(context.Context, string) error
	Export(context.Context, string, string, string) (string, error)
	Capabilities(context.Context) ([]map[string]any, error)
	// EnvList/EnvSet manage API keys in the project-local .env.
	// EnvList returns ONLY variable names (values are never shown);
	// EnvSet saves one secret (values are never logged or returned).
	EnvList(context.Context) ([]string, error)
	EnvSet(context.Context, string, string) error
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
	target    string
	result    map[string]any
}

// reviewedTarget returns the checkout target captured at review time.
// The Ctrl+S guard already forces signature equality, so begin() must scan
// the reviewed snapshot — never the live form field, which the user may
// have edited after Ctrl+E.
func (m *Model) reviewedTarget() string {
	if m.reviewed == nil {
		return ""
	}
	return m.reviewedCheckout
}

type Model struct {
	api                API
	embedded           bool
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
	reviewedCheckout   string
	dirty              bool
	status             string
	availability       string
	log                []string
	evidence           viewport.Model
	review             viewport.Model
	form               viewport.Model
	activity           viewport.Model
	advanced           bool
	editing            bool
	reviewMode         bool
	rawReview          bool
	rawEvidence        bool
	evidenceFocus      bool
	evidenceText       string
	evidenceRaw        string
	reviewText         string
	reviewRaw          string
	menu               bool
	menuCursor         int
	envNames           []string
	envStatus          string
	keysName           textinput.Model
	keysValue          textinput.Model
	keysFocus          int
	keyInput           bool
	activityID         string
	activityGeneration uint64
	savedActivity      service.RunActivity
	activeResult       map[string]any
	followActive       bool
	layoutWidth        int
	activityLoading    bool
}

var labels = []string{"Checkout", "Profile (fast/full)", "Configuration file", "Timeout (seconds)", "Maximum files", "Artifact directory", "Timezone", "Threshold", "Allow dirty (yes/no)", "Laya (yes/no)", "Laya configuration file", "Export format"}
var tabs = []string{"History", "Workspace", "Activity", "Findings", "Reports"}

func New(api API) Model {
	m := Model{api: api, tab: 1, width: 100, height: 35, status: "Loading scan workspace…", availability: "Checking scanner availability…", edited: make(map[int]bool)}
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
	m.keysName = textinput.New()
	m.keysName.Placeholder = "VARIABLE_NAME"
	m.keysName.CharLimit = 128
	m.keysName.SetWidth(60)
	m.keysValue = textinput.New()
	m.keysValue.Placeholder = "paste secret, then save"
	m.keysValue.EchoMode = textinput.EchoPassword
	m.keysValue.CharLimit = 4096
	m.keysValue.SetWidth(60)
	m.envStatus = "Loading saved keys…"
	m.historyTable = table.New(table.WithColumns([]table.Column{{Title: "ID", Width: 6}, {Title: "Run", Width: 24}, {Title: "Status", Width: 15}, {Title: "Attempt", Width: 7}, {Title: "Started", Width: 22}}), table.WithFocused(true), table.WithHeight(12))
	m.findingTable = table.New(table.WithColumns([]table.Column{{Title: "Severity", Width: 12}, {Title: "CWE", Width: 16}, {Title: "Status", Width: 15}, {Title: "Scanner", Width: 20}, {Title: "Title", Width: 40}}), table.WithFocused(true), table.WithHeight(10))
	m.evidence = viewport.New(viewport.WithWidth(96), viewport.WithHeight(8))
	m.evidence.SetContent("Select a finding and press Enter to inspect evidence.")
	m.review = viewport.New(viewport.WithWidth(96), viewport.WithHeight(10))
	m.review.SetContent("Press Ctrl+E to review effective settings, then Ctrl+S to start.")
	m.form = viewport.New(viewport.WithWidth(96), viewport.WithHeight(20))
	m.activity = viewport.New(viewport.WithWidth(96), viewport.WithHeight(20))
	m.review.SoftWrap, m.evidence.SoftWrap, m.activity.SoftWrap = true, true, true
	m.resize()
	return m
}

// NewEmbedded keeps scanner state separate from the chat host. The chat client
// owns navigation and model-key management when this view is embedded.
func NewEmbedded(api API) Model {
	m := New(api)
	m.embedded = true
	m.resize()
	return m
}
func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}
func (m Model) Init() tea.Cmd {
	return tea.Batch(tick(), func() tea.Msg { return loaded{kind: "init", err: m.api.Init(context.Background())} })
}

// keysCmd lists stored API-key names ONLY — values never cross this boundary.
func (m *Model) keysCmd() tea.Cmd {
	return func() tea.Msg {
		names, err := m.api.EnvList(context.Background())
		return loaded{kind: "keys", value: names, err: err}
	}
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
	for _, input := range m.inputs[:11] {
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
			return defaults, fmt.Errorf("Timeout must be a whole number of seconds")
		}
		flags["timeout"] = v
	}
	if values[4] != "100000" || edited[4] {
		v, err := strconv.Atoi(values[4])
		if err != nil {
			return defaults, fmt.Errorf("Maximum files must be a whole number")
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
	m.activeResult = nil
	m.activityID = ""
	m.savedActivity = service.RunActivity{}
	m.activityLoading = false
	m.activity.SetContent("Starting scan…")
	m.followActive = true
	m.editing, m.reviewMode = false, false
	m.tab = 2
	m.status = "Starting scan…"
	m.quitAfter = false
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelRun = cancel
	api, send, id := m.api, m.Send, m.selected
	config, checkout := m.reviewed, m.reviewedTarget()
	if checkout == "" {
		checkout = m.inputs[0].Value()
	}
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
		m.resize()
	case loaded:
		if msg.kind == "review" && msg.generation != m.reviewGeneration || msg.kind == "findings" && (msg.generation != m.generation || msg.id != m.selected) || msg.kind == "history" && msg.generation != m.historyGeneration || msg.kind == "activity" && (msg.generation != m.activityGeneration || msg.id != m.activityID) || msg.kind == "evidence" && (msg.generation != m.evidenceGeneration || msg.id != m.selected) {
			break
		}
		if msg.err != nil {
			if msg.kind == "activity" {
				m.activityLoading = false
			}
			m.status = msg.err.Error() + ". " + recoveryAdvice(msg.err.Error())
			if msg.kind == "review" {
				m.reviewText = "Review failed\n\n" + m.status
				m.review.SetContent(m.reviewText)
				m.reviewMode = true
			}
			break
		}
		switch msg.kind {
		case "init":
			m.ready = true
			m.status = "Ready"
			if !m.embedded {
				cmds = append(cmds, m.keysCmd())
			}
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
				detail := msg.value.(findingDetail)
				m.evidenceText, m.evidenceRaw = detail.text, detail.raw
				m.rawEvidence = false
				m.evidence.SetContent(detail.text)
				m.evidence.GotoTop()
				m.evidenceFocus = true
			}
		case "review":
			if msg.generation == m.reviewGeneration {
				result := msg.value.(reviewResult)
				data, _ := json.MarshalIndent(result.result, "", "  ")
				m.reviewText = reviewSummary(result.target, result.config, result.result)
				m.reviewRaw = string(data)
				m.rawReview = false
				m.review.SetContent(m.reviewText)
				m.review.GotoTop()
				m.reviewMode, m.editing = true, false
				m.reviewSignature = result.signature
				m.reviewed = &result.config
				m.reviewedCheckout = result.target
				m.status = "Settings reviewed. Ctrl+S starts this scan."
			}
		case "keys":
			if names, ok := msg.value.([]string); ok {
				m.envNames = names
			}
			if msg.err != nil {
				m.envStatus = msg.err.Error()
			} else if m.envStatus == "" || m.envStatus == "Loading saved keys…" {
				m.envStatus = fmt.Sprintf("%d key(s) stored (values never shown)", len(m.envNames))
			}
		case "export":
			m.status = "Exported: " + msg.value.(string)
		case "cancel":
			m.status = "Cancellation requested; preserving partial evidence…"
		case "activity":
			if msg.generation == m.activityGeneration && msg.id == m.activityID {
				m.savedActivity = msg.value.(service.RunActivity)
				m.activityLoading = false
				if msg.id != m.activePK {
					m.status = "Saved activity: " + m.savedActivity.RunID + " · " + m.savedActivity.Status
				}
				m.refreshActivity()
				if msg.id != m.activePK {
					m.activity.GotoTop()
				}
			}
		case "completion":
			if msg.id == m.inputs[0].Value() {
				completion := msg.value.(pathCompletion)
				m.inputs[0].SetValue(completion.value)
				m.inputs[0].CursorEnd()
				m.status = completion.hint
				if msg.id != completion.value {
					m.invalidateReview(0)
				}
			}
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
			if m.followActive {
				m.selected = m.activePK
				m.activityID = m.activePK
				m.page.Offset = 0
				m.generation++
			}
		}
		m.log = append(m.log, eventText(e))
		if len(m.log) > 200 {
			m.log = m.log[len(m.log)-200:]
		}
		m.dirty = true
		m.refreshActivity()
	case finishedMsg:
		m.scanning = false
		if m.cancelRun != nil {
			m.cancelRun()
		}
		m.cancelRun = nil
		m.activeResult = msg.result
		if m.activePK == "" && msg.result["id"] != nil {
			m.activePK, m.active = fmt.Sprint(msg.result["id"]), display(msg.result["run_id"])
			if m.followActive {
				m.selected, m.activityID = m.activePK, m.activePK
			}
		}
		if msg.err != nil {
			m.status = msg.err.Error() + ". " + recoveryAdvice(msg.err.Error())
			m.log = append(m.log, m.status)
		} else {
			m.status = fmt.Sprintf("%v: %v | gate %v | exit %v", msg.result["run_id"], msg.result["status"], msg.result["gate"], msg.result["exit_code"])
		}
		m.refreshActivity()
		if m.activityID == m.activePK {
			m.activityGeneration++
			m.activityLoading = false
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
		if m.scanning {
			m.refreshActivity()
			if m.tab == 2 && m.activePK != "" && m.activityID == m.activePK && !m.activityLoading {
				cmds = append(cmds, m.activityCmd(m.activePK))
			}
		}
		if m.ready && m.tab == 3 && m.dirty && m.selected == m.activePK {
			m.dirty = false
			m.generation++
			cmds = append(cmds, m.findingsCmd())
		}
	case tea.KeyPressMsg:
		updated, cmd := m.handleKey(msg)
		state := updated.(Model)
		state.resize()
		return state, cmd
	case tea.MouseClickMsg:
		if m.embedded {
			return m.embeddedMouse(msg)
		}
	case tea.MouseWheelMsg:
		if m.embedded {
			var cmd tea.Cmd
			switch {
			case m.tab == 0:
				m.historyTable, cmd = m.historyTable.Update(msg)
			case m.tab == 2:
				m.activity, cmd = m.activity.Update(msg)
			case m.tab == 3 && m.evidenceFocus:
				m.evidence, cmd = m.evidence.Update(msg)
			case m.tab == 3:
				m.findingTable, cmd = m.findingTable.Update(msg)
			case m.reviewMode:
				m.review, cmd = m.review.Update(msg)
			}
			return m, cmd
		}
	default:
		return m.handleInput(msg)
	}
	m.resize()
	return m, tea.Batch(cmds...)
}
