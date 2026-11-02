package chat

import (
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

type inertBaseline struct{ messages int }

func (b inertBaseline) Init() tea.Cmd                       { return nil }
func (b inertBaseline) View() tea.View                      { return tea.NewView("baseline") }
func (b inertBaseline) Update(tea.Msg) (tea.Model, tea.Cmd) { b.messages++; return b, nil }

func TestPasteStillGoesToChatAfterVisitingBaseline(t *testing.T) {
	m, _ := setup()
	m.screen = chatScreen
	m.baseline = inertBaseline{}
	m = click(m, "tab:1")
	m = click(m, "tab:0")
	m = step(m, tea.PasteMsg{Content: "investigate this code"})
	if m.input.Value() != "investigate this code" {
		t.Fatal("baseline stole pasted chat input")
	}
}
func TestMouseKeyboardAndFocusStayInsideAutoConfirmation(t *testing.T) {
	m, h := setup()
	m.screen = chatScreen
	m.input.SetValue("/mode auto")
	m = press(m, tea.KeyEnter)
	m = click(m, "tab:1")
	if m.tab != tabChat || len(h.sent) != 0 {
		t.Fatal("click escaped modal")
	}
	m = step(m, tea.BlurMsg{})
	if m.confirmAuto {
		t.Fatal("focus loss kept confirmation open")
	}
}
func TestPendingBannerKeyboardActionsDoNotSubmitWhileBusy(t *testing.T) {
	m, h := setup()
	m.screen = chatScreen
	m.busy = true
	m = step(m, event("pending", map[string]any{"items": []map[string]any{{"id": "p1", "files": []string{"A.java"}}}}))
	m = click(m, "pending:review:p1")
	if len(h.sent) != 0 {
		t.Fatal("review sent during turn")
	}
	m.busy = false
	m = press(m, 'r')
	if len(h.sent) != 1 {
		t.Fatal("banner key did not relay")
	}
}
func TestRestartOnlyStartsOneReplacementAndReadsReadySessionLog(t *testing.T) {
	m, _ := setup()
	replacement := &fakeHost{}
	m.Restart = func() (Host, error) { return replacement, nil }
	m = step(m, event("ready", map[string]any{"target": "project", "provider": "local", "model": "small", "mode": "auto", "session_log": "saved.jsonl"}))
	m = step(m, disconnectedMsg{})
	updated, cmd := m.Update(tea.KeyPressMsg{Code: 'r'})
	m = updated.(Model)
	if cmd == nil || !m.restarting {
		t.Fatal("restart is not marked in progress")
	}
	_, again := m.Update(tea.KeyPressMsg{Code: 'r'})
	if again != nil {
		t.Fatal("second restart launched")
	}
	m = step(m, cmd())
	if replacement.sent[1]["resume"] != "saved.jsonl" {
		t.Fatal("ready log not resumed")
	}
}
func TestLastWrappedDiffLineMustBeVisible(t *testing.T) {
	m, h := setup()
	m = gate(m, "G6", "+"+strings.Repeat("x", 4000)+"LAST")
	if m.dialog.diffSeenEnd {
		t.Fatal("long line unlocked without wrapping")
	}
	m = press(m, 'a')
	if len(h.sent) != 0 {
		t.Fatal("apply bypassed wrapped diff")
	}
	m = press(m, tea.KeyEnd)
	if !strings.Contains(m.View().Content, "LAST") {
		t.Fatal("last wrapped line clipped")
	}
	m = press(m, 'a')
	if len(h.sent) != 1 {
		t.Fatal("end did not unlock")
	}
}
func TestKeysSelectionClampsAfterModelRemoval(t *testing.T) {
	m, _ := setup()
	m = models(m, true, true)
	m.keysIndex = 8
	m = models(m, true, true)
	m.tab = tabKeys
	m = press(m, tea.KeyEnter)
	if m.form == nil || m.form.alias != "my-model" {
		t.Fatal("selection not clamped")
	}
}

func TestHostUserEchoUsesHumanLabelOnce(t *testing.T) {
	m, _ := setup()
	m.screen = chatScreen
	m.input.SetValue("inspect changes")
	m = press(m, tea.KeyEnter)
	m = step(m, event("text_delta", map[string]any{"role": "user", "text": "inspect changes"}))
	if strings.Count(m.transcriptText(), "inspect changes") != 1 || strings.Contains(m.transcriptText(), "AI hỗ trợ › inspect changes") {
		t.Fatal("user echo duplicated or mislabeled")
	}
	m = step(m, event("text_delta", map[string]any{"role": "user", "text": "remote human request"}))
	if !strings.Contains(m.transcriptText(), "you › remote human request") {
		t.Fatal("remote human mislabeled")
	}
}
func TestExplicitAutoConfirmationMatchesHostContract(t *testing.T) {
	for _, mouse := range []bool{false, true} {
		m, h := setup()
		m.screen = chatScreen
		m.input.SetValue("/mode auto")
		m = press(m, tea.KeyEnter)
		if mouse {
			m = click(m, "auto:yes")
		} else {
			m = press(m, 'y')
		}
		if len(h.sent) != 1 || !reflect.DeepEqual(h.sent[0]["args"], []string{"auto", "confirm"}) {
			t.Fatal("host needs explicit confirmation marker")
		}
	}
}
