package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
	"devsecops-agent/internal/service"
)

type fakeAPI struct{ calls int }

func (f *fakeAPI) Notification(context.Context, map[string]any) (service.NotificationResponse, error) {
	f.calls++
	return service.NotificationResponse{}, nil
}

func (f *fakeAPI) ModelProfiles(context.Context) ([]service.ModelProfile, error) {
	return nil, nil
}

func (f *fakeAPI) Init(context.Context) error                            { f.calls++; return nil }
func (f *fakeAPI) History(context.Context) ([]service.RunSummary, error) { f.calls++; return nil, nil }
func (f *fakeAPI) Activity(context.Context, string) (service.RunActivity, error) {
	f.calls++
	return service.RunActivity{}, nil
}
func (f *fakeAPI) Findings(context.Context, string, string, int) (service.FindingPage, error) {
	f.calls++
	return service.FindingPage{}, nil
}
func (f *fakeAPI) Finding(context.Context, string, string) (json.RawMessage, error) {
	f.calls++
	return nil, nil
}
func (f *fakeAPI) Review(context.Context, string, service.Config) (map[string]any, error) {
	f.calls++
	return nil, nil
}
func (f *fakeAPI) Run(context.Context, map[string]any, func(bridge.Event)) (map[string]any, error) {
	f.calls++
	return nil, nil
}
func (f *fakeAPI) Retry(context.Context, string, func(bridge.Event)) (map[string]any, error) {
	f.calls++
	return nil, nil
}
func (f *fakeAPI) Cancel(context.Context, string) error { f.calls++; return nil }
func (f *fakeAPI) Export(context.Context, string, string, string) (string, error) {
	f.calls++
	return "", nil
}
func (f *fakeAPI) Capabilities(context.Context) ([]map[string]any, error) { f.calls++; return nil, nil }
func (f *fakeAPI) EnvList(context.Context) ([]string, error) {
	f.calls++
	return []string{"MISTRAL_API_KEY"}, nil
}
func (f *fakeAPI) EnvSet(context.Context, string, string) error { f.calls++; return nil }
func page(count int) service.FindingPage {
	items := []service.FindingSummary{}
	for i := 0; i < count; i++ {
		items = append(items, service.FindingSummary{FindingID: fmt.Sprint(i), Severity: "high", CWE: "CWE-89", Status: "unprocessed", Scanner: "semgrep", Title: "SQL injection"})
	}
	return service.FindingPage{RunSummary: service.RunSummary{ID: 1, Revision: 1}, Items: items, Total: 10000, Limit: 200}
}
func TestQR21NavigationDoesNotCallServices(t *testing.T) {
	api := &fakeAPI{}
	m := New(api)
	m.ready = true
	updated, _ := m.Update(tea.KeyPressMsg{Code: 'n', Mod: tea.ModCtrl})
	m = updated.(Model)
	if m.tab != 1 || api.calls != 0 {
		t.Fatal("navigation performed synchronous service work")
	}
	// Configuration-file I/O must also remain inside the command.
	m.inputs[2].SetValue("missing-configuration-file.json")
	updated, cmd := m.Update(tea.KeyPressMsg{Code: 'e', Mod: tea.ModCtrl})
	m = updated.(Model)
	if cmd == nil || api.calls != 0 || m.status != "Reviewing checkout…" {
		t.Fatal("configuration review blocked the event loop")
	}
}
func TestFR71RefreshPreservesCursorAndRejectsStaleRun(t *testing.T) {
	m := New(&fakeAPI{})
	m.ready = true
	m.selected = "1"
	m.generation = 2
	updated, _ := m.Update(loaded{kind: "findings", id: "1", generation: 2, value: page(200)})
	m = updated.(Model)
	m.findingTable.SetCursor(10)
	refresh := page(200)
	refresh.Items[20].Title = "Updated evidence"
	updated, _ = m.Update(loaded{kind: "findings", id: "1", generation: 2, value: refresh})
	m = updated.(Model)
	if m.findingTable.Cursor() != 10 {
		t.Fatal("refresh reset cursor")
	}
	updated, _ = m.Update(loaded{kind: "findings", id: "2", generation: 1, value: page(1)})
	m = updated.(Model)
	if len(m.page.Items) != 200 || m.selected != "1" {
		t.Fatal("stale run replaced viewed findings")
	}
}
func TestFR71ActiveScanDoesNotReplaceHistoricalRun(t *testing.T) {
	api := &fakeAPI{}
	m := New(api)
	m.ready = true
	m.scanning = true
	m.active = "run-2"
	m.activePK = "2"
	m.selected = "1"
	m.tab = 3
	m.dirty = true
	updated, _ := m.Update(tickMsg{})
	m = updated.(Model)
	if m.selected != "1" || m.generation != 0 || api.calls != 0 {
		t.Fatal("active scan refreshed a historical run")
	}
}
func TestQR21SettingsFieldsStayVisible(t *testing.T) {
	m := New(&fakeAPI{})
	m.ready = true
	updated, _ := m.Update(tea.KeyPressMsg{Code: '5', Text: "5"})
	m = updated.(Model)
	if m.tab != 4 || m.field != 5 {
		t.Fatal("settings focused an invisible setup field")
	}
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	m = updated.(Model)
	if m.field != 11 {
		t.Fatal("settings field navigation failed")
	}
}
func TestFR71EmptyFilterAndClipboard(t *testing.T) {
	m := New(&fakeAPI{})
	m.ready = true
	m.selected = "1"
	m.generation = 1
	m.tab = 3
	updated, _ := m.Update(loaded{kind: "findings", id: "1", generation: 1, value: service.FindingPage{Items: []service.FindingSummary{}}})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = updated.(Model)
	updated, _ = m.Update(loaded{kind: "findings", id: "1", generation: 1, value: page(2)})
	m = updated.(Model)
	if len(m.page.Items) != 2 {
		t.Fatal("results did not recover after an empty filter")
	}
	updated, _ = m.Update(tea.KeyPressMsg{Code: 'n', Mod: tea.ModCtrl})
	m = updated.(Model)
	m.inputs[0].SetValue("")
	updated, _ = m.Update(tea.PasteMsg{Content: "C:/work/checkout"})
	m = updated.(Model)
	if m.inputs[0].Value() != "C:/work/checkout" {
		t.Fatal("clipboard messages were not delivered to the focused input")
	}
}
func TestScanSendsReviewedTargetNotEditedFields(t *testing.T) {
	// begin() must scan the reviewed snapshot, not the live form field.
	// Regression: Ctrl+E reviewed checkout A, user edited the form to B,
	// Ctrl+S guard blocks until re-review; restoring A scans A.
	reviewed := service.Config{Profile: "fast"}
	m := New(&fakeAPI{})
	m.ready = true
	m.reviewed = &reviewed
	m.reviewSignature = m.signature()
	m.reviewedCheckout = "C:/work/reviewed-checkout"
	m.inputs[0].SetValue("C:/work/attacker-swapped")
	if m.reviewedTarget() != "C:/work/reviewed-checkout" {
		t.Fatalf("review snapshot lost: %q", m.reviewedTarget())
	}
}
func BenchmarkQR21Navigation(b *testing.B) {
	m := New(&fakeAPI{})
	m.ready = true
	m.selected = "1"
	m.generation = 1
	m.tab = 3
	updated, _ := m.Update(loaded{kind: "findings", id: "1", generation: 1, value: page(200)})
	m = updated.(Model)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
		m = updated.(Model)
		_ = m.View()
	}
}
func TestQR21NavigationLatencyAtTenThousandFindings(t *testing.T) {
	m := New(&fakeAPI{})
	m.ready = true
	m.selected = "1"
	m.generation = 1
	m.tab = 3
	updated, _ := m.Update(loaded{kind: "findings", id: "1", generation: 1, value: page(200)})
	m = updated.(Model)
	samples := []time.Duration{}
	for i := 0; i < 100; i++ {
		started := time.Now()
		updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
		m = updated.(Model)
		_ = m.View()
		samples = append(samples, time.Since(started))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p95 := samples[95]
	t.Logf("10,000 findings, 200-row page: navigation/update/view p95 %.3f ms (terminal output excluded)", float64(p95)/float64(time.Millisecond))
	if p95 > 100*time.Millisecond {
		t.Fatalf("navigation exceeds responsiveness target: %v", p95)
	}
}

func TestKeysSaveNeverRevealsValues(t *testing.T) {
	m := New(&fakeAPI{})
	m.ready = true
	m.tab = 1
	// Names-only listing: the value field must not leak into names/status.
	updated, _ := m.Update(loaded{kind: "keys", value: []string{"MISTRAL_API_KEY"}})
	m = updated.(Model)
	if len(m.envNames) != 1 || m.envNames[0] != "MISTRAL_API_KEY" {
		t.Fatalf("expected one stored key name, got %v", m.envNames)
	}
	for _, view := range []string{m.review.View(), fmt.Sprint(m.envStatus)} {
		if strings.Contains(view, "secret") {
			t.Fatal("stored listing leaked a secret value")
		}
	}
	// Saving clears the value input immediately (pass-through, then drop).
	m.tab = 1
	m.keysName.SetValue("provider_api_key")
	m.keysValue.SetValue("sensitivesecret")
	updated, cmd := m.Update(tea.KeyPressMsg{Code: 'k', Mod: tea.ModCtrl})
	m = updated.(Model)
	if cmd == nil {
		t.Fatal("Ctrl+K produced no save command")
	}
	if m.keysValue.Value() != "" {
		t.Fatal("value field was not cleared on save")
	}
	// Key entry focuses name first; Tab cycles name -> value.
	m.keysName.SetValue("")
	updated, _ = m.Update(tea.KeyPressMsg{Code: 'k', Mod: tea.ModCtrl})
	m = updated.(Model)
	if !m.keyInput || m.keysFocus != 0 {
		t.Fatal("Ctrl+K with empty name did not enter key-input mode")
	}
}
