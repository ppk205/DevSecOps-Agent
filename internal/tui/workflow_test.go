package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
	"devsecops-agent/internal/service"
	"github.com/charmbracelet/x/ansi"
)

type workflowAPI struct {
	fakeAPI
	retried, exported, exportedOutput string
	configuration                     any
}

func (f *workflowAPI) History(context.Context) ([]service.RunSummary, error) {
	return []service.RunSummary{{ID: 2, RunID: "run-b", Status: "completed"}, {ID: 1, RunID: "run-a", Status: "completed"}}, nil
}
func (f *workflowAPI) Activity(_ context.Context, id string) (service.RunActivity, error) {
	return service.RunActivity{RunSummary: service.RunSummary{RunID: "run-" + id, Status: "failed"}, Events: []bridge.Event{{RunID: "run-" + id, Stage: "semgrep", Status: "completed"}}, Result: map[string]any{"errors": []string{"report export failed: disk full"}}}, nil
}
func (f *workflowAPI) Findings(_ context.Context, id, query string, offset int) (service.FindingPage, error) {
	result := page(1)
	result.RunID, result.Total = "run-"+id, 1
	return result, nil
}
func (f *workflowAPI) Finding(context.Context, string, string) (json.RawMessage, error) {
	return json.RawMessage(`{"title":"SQL injection","severity":"high","cwe_category":"CWE-89","status":"unprocessed","finding_id":"finding-a","description":"Untrusted query input","observations":[{"tool":"semgrep","rule_id":"sql-injection","message":"Check query construction","location":{"file_path":"Example.java","line_start":1,"snippet":"class Example {}"}}]}`), nil
}
func (f *workflowAPI) Review(_ context.Context, checkout string, config service.Config) (map[string]any, error) {
	return map[string]any{"manifest": map[string]any{"commit": "verified-commit", "inventory": []any{"Example.java"}, "files": strings.Repeat("long retained manifest\n", 100)}}, nil
}
func (f *workflowAPI) Run(_ context.Context, params map[string]any, _ func(bridge.Event)) (map[string]any, error) {
	f.configuration = params["configuration"]
	return map[string]any{"id": 3, "run_id": "run-new", "status": "completed", "gate": "passed", "exit_code": 0, "findings": 1}, nil
}
func (f *workflowAPI) Retry(_ context.Context, id string, _ func(bridge.Event)) (map[string]any, error) {
	f.retried = id
	return map[string]any{"id": 3, "run_id": "run-new", "status": "completed", "gate": "passed", "exit_code": 0}, nil
}
func (f *workflowAPI) Export(_ context.Context, id, format, output string) (string, error) {
	f.exported, f.exportedOutput = id, output
	return output + "/export." + format, nil
}
func keyState(m Model, key tea.KeyPressMsg) (Model, tea.Cmd) {
	state, cmd := m.Update(key)
	return state.(Model), cmd
}
func deliver(m Model, cmd tea.Cmd) Model {
	if cmd == nil {
		return m
	}
	message := cmd()
	if commands, ok := message.(tea.BatchMsg); ok {
		for _, child := range commands {
			m = deliver(m, child)
		}
		return m
	}
	switch message.(type) {
	case loaded, finishedMsg, searchMsg:
		updated, next := m.Update(message)
		return deliver(updated.(Model), next)
	}
	return m
}
func readyWorkflow(t *testing.T) (Model, *workflowAPI) {
	t.Helper()
	api := &workflowAPI{}
	m := New(api)
	m.ready = true
	m.status = "Ready"
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = updated.(Model)
	m = deliver(m, m.historyCmd())
	return m, api
}
func press(m Model, key tea.KeyPressMsg) Model {
	state, cmd := keyState(m, key)
	return deliver(state, cmd)
}
func ctrl(code rune) tea.KeyPressMsg { return tea.KeyPressMsg{Code: code, Mod: tea.ModCtrl} }

func TestFR70HistoryActionsUseHighlightedRunWithoutOpeningIt(t *testing.T) {
	for _, action := range []rune{'t', 'o'} {
		m, api := readyWorkflow(t)
		m = press(m, ctrl('1'))
		m = press(m, tea.KeyPressMsg{Code: tea.KeyDown})
		m = press(m, tea.KeyPressMsg{Code: tea.KeyEnter}) // Inspect A.
		m = press(m, ctrl('1'))
		m = press(m, tea.KeyPressMsg{Code: tea.KeyUp}) // Highlight B.
		m = press(m, ctrl(action))
		actual := api.retried
		if action == 'o' {
			actual = api.exported
		}
		if actual != "2" {
			t.Fatalf("Ctrl+%c acted on %q instead of highlighted run B", action, actual)
		}
	}
	m, api := readyWorkflow(t)
	m = press(m, ctrl('1'))
	_ = press(m, ctrl('t'))
	if api.retried != "2" {
		t.Fatal("fresh history selection could not be retried")
	}
}
func TestFR71QR21KeyboardWorkflowReviewInspectExport(t *testing.T) {
	m, api := readyWorkflow(t)
	m, _ = keyState(m, ctrl('n'))
	updated, _ := m.Update(tea.PasteMsg{Content: "-fixture"})
	m = updated.(Model)
	m = press(m, tea.KeyPressMsg{Code: tea.KeyTab}) // Profile.
	m = press(m, tea.KeyPressMsg{Code: tea.KeyTab}) // Advanced.
	m = press(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	for i := 0; i < 4; i++ {
		m = press(m, tea.KeyPressMsg{Code: tea.KeyTab}) // Output directory.
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = press(m, ctrl('u'))
	updated, _ = m.Update(tea.PasteMsg{Content: t.TempDir()})
	m = updated.(Model)
	output := m.inputs[5].Value()
	m = press(m, ctrl('e'))
	if m.reviewed == nil || !strings.Contains(m.View().Content, "verified-commit") {
		t.Fatal("keyboard review did not display the committed checkout")
	}
	m = press(m, tea.KeyPressMsg{Code: 'v', Text: "v"})
	m = press(m, tea.KeyPressMsg{Code: tea.KeyPgDown})
	if m.review.YOffset() == 0 {
		t.Fatal("full manifest could not be scrolled")
	}
	m = press(m, ctrl('s'))
	if api.configuration == nil || m.scanning || m.selected != "3" {
		t.Fatal("reviewed scan did not complete through keyboard actions")
	}
	m = press(m, ctrl('4'))
	m = press(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.evidenceFocus || !strings.Contains(m.View().Content, "Example.java:1") || !strings.Contains(m.View().Content, "class Example") {
		t.Fatal("finding detail did not present retained source evidence")
	}
	m = press(m, tea.KeyPressMsg{Code: 'v', Text: "v"})
	if !strings.Contains(m.View().Content, "cwe_category") {
		t.Fatal("raw finding details are inaccessible")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	m = press(m, ctrl('o'))
	if api.exported != "3" || api.exportedOutput != output {
		t.Fatal("export did not use the opened run and reviewed output directory")
	}
	_, quit := keyState(m, ctrl('q'))
	if quit == nil {
		t.Fatal("keyboard quit was inaccessible")
	}
}
func TestFR71ReviewSurvivesCursorMovementButRejectsEdits(t *testing.T) {
	m, _ := readyWorkflow(t)
	m, pending := keyState(m, ctrl('e'))
	m = press(m, tea.KeyPressMsg{Code: tea.KeyLeft})
	m = deliver(m, pending)
	if m.reviewed == nil {
		t.Fatal("cursor movement discarded a valid review")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = press(m, tea.KeyPressMsg{Code: 'x', Text: "x"})
	if m.reviewed != nil {
		t.Fatal("editing the checkout did not invalidate its review")
	}
}
func TestQR16TerminalFailuresAndSavedRunEventsRemainVisible(t *testing.T) {
	m, _ := readyWorkflow(t)
	m.tab, m.followActive = 2, true
	updated, _ := m.Update(finishedMsg{result: map[string]any{"id": 3, "run_id": "run-new", "status": "failed", "gate": "failed", "exit_code": 2, "errors": []string{"report export failed: disk full"}}})
	m = updated.(Model)
	if !strings.Contains(m.activity.View(), "disk full") || !strings.Contains(m.activity.View(), "Next:") {
		t.Fatal("terminal report error and corrective action disappeared")
	}
	m = press(m, ctrl('1'))
	m = press(m, ctrl('3'))
	if !strings.Contains(m.View().Content, "Saved activity") || strings.Contains(m.View().Content, "run-new") || !strings.Contains(m.View().Content, "semgrep") {
		t.Fatal("history activity was replaced by the previous scan")
	}
}
func TestQR21AllViewsAndFocusedControlsFitTerminal(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {75, 26}, {60, 20}, {45, 12}} {
		m, _ := readyWorkflow(t)
		updated, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = updated.(Model)
		m.availability = strings.Repeat("scanner: unavailable | ", 8)
		for tab := range tabs {
			m.tab = tab
			for _, field := range []int{0, 10, startControl} {
				m.advanced, m.field = true, field
				text := m.View().Content
				lines := strings.Split(text, "\n")
				if len(lines) > size[1] {
					t.Fatalf("%dx%d tab %d exceeds terminal height: %d", size[0], size[1], tab, len(lines))
				}
				for _, line := range lines {
					if width := ansi.StringWidth(line); width > size[0] {
						t.Fatalf("%dx%d tab %d line exceeds terminal width: %d", size[0], size[1], tab, width)
					}
				}
				if tab == 1 && field == 10 && size[0] >= 60 && !strings.Contains(text, "Laya configuration") {
					t.Fatal("focused advanced field was clipped")
				}
			}
		}
	}
}
func TestFR71TypedChoicesAndActionsAreReachableWhileEditing(t *testing.T) {
	m, _ := readyWorkflow(t)
	m, _ = keyState(m, ctrl('n'))
	m = press(m, ctrl('5'))
	if m.tab != 4 {
		t.Fatal("editing trapped tab navigation")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyTab})
	if m.field != 11 {
		t.Fatal("report format control was inaccessible")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.inputs[11].Value() != "sarif" || m.inputs[0].Value() != "." {
		t.Fatal("typed choice changed an unrelated input")
	}
	m = press(m, ctrl('k'))
	if !strings.Contains(m.View().Content, "Actions") {
		t.Fatal("action menu could not be opened")
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.tab != 1 || m.menu {
		t.Fatal("action menu did not execute New scan")
	}
}
func TestQR01FindingSummaryDoesNotInventSourceOrVerification(t *testing.T) {
	detail, err := describeFinding(json.RawMessage(`{"title":"Finding","status":"unprocessed","observations":[{"location":{"file_path":"Missing.java","line_start":7}}]}`))
	if err != nil || !strings.Contains(detail.text, "No source excerpt was retained") || !strings.Contains(detail.text, "Verification / review: unprocessed") || !strings.Contains(detail.text, "No evidence record references") {
		t.Fatal(fmt.Sprint(err), "missing evidence was not explicit")
	}
}

func TestQR01ConfirmedFindingPreservesEvidenceReferences(t *testing.T) {
	detail, err := describeFinding(json.RawMessage(`{"title":"Verified finding","status":"confirmed","evidence_refs":["record-a"]}`))
	if err != nil || !strings.Contains(detail.text, "Verification / review: confirmed") || !strings.Contains(detail.text, "record-a") || strings.Contains(detail.text, "No evidence record") {
		t.Fatal("recorded validation state or evidence references were misrepresented")
	}
}

func TestQR21SmallTerminalQuitWaitsForPartialEvidence(t *testing.T) {
	m, _ := readyWorkflow(t)
	m.width, m.height, m.scanning = 45, 12, true
	cancelled := false
	m.cancelRun = func() { cancelled = true }
	m, _ = keyState(m, ctrl('q'))
	if !strings.Contains(m.View().Content, "cancel and quit") {
		t.Fatal("resize warning hid the cancellation choice")
	}
	m, cmd := keyState(m, tea.KeyPressMsg{Code: 'y', Text: "y"})
	if !cancelled || !m.quitAfter || cmd != nil {
		t.Fatal("quit did not wait for the scan to retain partial evidence")
	}
	_, cmd = m.Update(finishedMsg{result: map[string]any{"status": "cancelled", "exit_code": 130}})
	if cmd == nil {
		t.Fatal("completed cancellation did not permit quitting")
	}
}

func TestDR09FirstActiveEventDoesNotInvalidateHistoricalView(t *testing.T) {
	m, _ := readyWorkflow(t)
	m.scanning, m.followActive = true, false
	m.selected, m.activityID = "1", "1"
	m.page.Offset, m.generation = 200, 8
	updated, _ := m.Update(progressMsg(bridge.Event{RunID: "run-new", PK: 3, Stage: "intake", Status: "running"}))
	m = updated.(Model)
	if m.selected != "1" || m.activityID != "1" || m.page.Offset != 200 || m.generation != 8 {
		t.Fatal("the first event reset or invalidated a historical page")
	}
}

func TestQR21CheckoutTypingSurvivesWorkspaceInitialization(t *testing.T) {
	api := &fakeAPI{}
	m := New(api)
	m, _ = keyState(m, ctrl('n'))
	m, _ = keyState(m, tea.KeyPressMsg{Code: 'x', Text: "x"})
	if m.inputs[0].Value() != ".x" || api.calls != 0 {
		t.Fatal("typing was discarded or performed I/O during initialization")
	}
}
