package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/service"
)

func TestFR71ArrowKeysMoveBetweenWorkspaceControlsWithoutChangingValues(t *testing.T) {
	api := &fakeAPI{}
	m := New(api)
	m.ready = true
	cfg := service.Defaults()
	m.reviewed = &cfg
	signature := m.signature()
	for _, field := range []int{1, aiModeControl, advancedControl, reviewControl, startControl, 0} {
		m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyDown})
		if m.field != field {
			t.Fatalf("Down selected %d, want %d", m.field, field)
		}
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyUp})
	if m.field != startControl || m.signature() != signature || m.reviewed == nil || api.calls != 0 {
		t.Fatal("arrow navigation changed configuration, review or performed service work")
	}
}

func TestFR71ArrowKeysKeepTextCursorAndChoiceEditing(t *testing.T) {
	m, _ := readyWorkflow(t)
	m.inputs[0].SetValue("abc")
	m.inputs[0].CursorEnd()
	m = press(m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = press(m, tea.KeyPressMsg{Code: tea.KeyLeft})
	m = press(m, tea.KeyPressMsg{Code: 'X', Text: "X"})
	if m.tab != 1 || m.inputs[0].Value() != "abXc" {
		t.Fatal("Left did not remain a text-cursor key while editing")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.field != 1 || m.editing || m.inputs[0].Focused() {
		t.Fatal("Down did not leave text editing and focus the next control")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.tab != 1 || m.inputs[1].Value() != "full" {
		t.Fatal("Right did not cycle the focused choice")
	}
	if strings.Contains(m.footer(), "Tab:") {
		t.Fatal("the primary navigation hint still requires Tab")
	}
}

func TestFR71LeftRightNavigateSectionsOutsideTextAndChoices(t *testing.T) {
	m, _ := readyWorkflow(t)
	for _, tab := range []int{2, 3, 4, 0, 1} {
		m = press(m, tea.KeyPressMsg{Code: tea.KeyRight})
		if m.tab != tab {
			t.Fatalf("Right opened tab %d, want %d", m.tab, tab)
		}
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyLeft})
	if m.tab != 0 {
		t.Fatal("Left did not open the previous section")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.historyTable.Cursor() != 1 {
		t.Fatal("Down stopped navigating history rows")
	}
}

func TestFR71ArrowNavigationPreservesReaderScrolling(t *testing.T) {
	m, _ := readyWorkflow(t)
	m.reviewMode = true
	m.review.SetHeight(3)
	m.review.SetContent(strings.Repeat("review line\n", 100))
	m = press(m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.review.YOffset() == 0 || m.field != 0 || m.tab != 1 {
		t.Fatal("Down changed form focus instead of scrolling the review")
	}
	m = press(m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.tab != 1 || !m.reviewMode {
		t.Fatal("section navigation interrupted the focused reader")
	}
}

func TestFR71ArrowKeysMoveBetweenKeyEntryFieldsWithoutSaving(t *testing.T) {
	api := &fakeAPI{}
	m := New(api)
	m.ready, m.keyInput = true, true
	m.keysName.Focus()
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.keysFocus != 1 || !m.keysValue.Focused() || m.keysName.Focused() {
		t.Fatal("Down did not focus the hidden value field")
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyUp})
	if m.keysFocus != 0 || !m.keysName.Focused() || m.keysValue.Focused() || api.calls != 0 {
		t.Fatal("Up did not return to the name without saving")
	}
	m, _ = keyState(m, ctrl('5'))
	if m.keyInput || m.keysName.Focused() || m.keysValue.Focused() {
		t.Fatal("changing views retained a hidden key-entry focus")
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyLeft})
	if m.tab != 3 {
		t.Fatal("leaving key entry prevented arrow view navigation")
	}
}
