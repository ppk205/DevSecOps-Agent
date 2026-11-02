package chat

import (
	tea "charm.land/bubbletea/v2"
	"strings"
	"testing"
)

func TestEnterWithoutHighlightNeverAnswers(t *testing.T) {
	for _, g := range []string{"G0", "G1", "G2", "G3", "G4", "G5", "G6", "G7"} {
		m, h := setup()
		m = gate(m, g, "+fix")
		m = press(m, tea.KeyEnter)
		if len(h.sent) != 0 || m.dialog == nil || m.dialog.highlight != -1 {
			t.Fatal(g)
		}
	}
}
func TestArrowThenEnterAnswers(t *testing.T) {
	m, h := setup()
	m = gate(m, "G3", "")
	m = press(m, tea.KeyRight)
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 1 || h.sent[0]["choice"] != "approve" {
		t.Fatal(h.sent)
	}
	m, _ = setup()
	m = gate(m, "G3", "")
	m = press(m, tea.KeyLeft)
	if m.dialog.highlight != 2 {
		t.Fatal("left must select last button")
	}
}
func TestLetterAndClickAnswer(t *testing.T) {
	for _, mouse := range []bool{false, true} {
		m, h := setup()
		m = gate(m, "G3", "")
		if mouse {
			m = click(m, "gate:reject")
		} else {
			m = press(m, 'n')
		}
		if m.dialog.form != "reason" {
			t.Fatal("no reason box")
		}
		m = press(m, tea.KeyEscape)
		if len(h.sent) != 0 || m.dialog == nil || m.dialog.form != "" {
			t.Fatal("Esc answered")
		}
	}
}
func TestEscAndFocusLossLeaveUndecided(t *testing.T) {
	for _, msg := range []tea.Msg{tea.KeyPressMsg{Code: tea.KeyEscape}, tea.BlurMsg{}} {
		m, h := setup()
		m = gate(m, "G3", "")
		m = step(m, msg)
		if m.dialog != nil || len(h.sent) != 0 || !strings.Contains(m.transcriptText(), "G3 left undecided") {
			t.Fatal("gate was answered")
		}
	}
}
func TestDangerousMarked(t *testing.T) {
	for _, g := range []string{"G0", "G3", "G6"} {
		m, _ := setup()
		m = gate(m, g, "+fix")
		if strings.Contains(m.View().Content, "DANGEROUS") != (g != "G3") {
			t.Fatal(g)
		}
	}
}
func TestG6ButtonsUnlockOnlyAtDiffEnd(t *testing.T) {
	for _, how := range []string{"end", "pagedown", "wheel", "down"} {
		t.Run(how, func(t *testing.T) {
			m, h := setup()
			m = gate(m, "G6", strings.Repeat("+unchanged long line\n", 1999)+"+last")
			m = press(m, 'a')
			if len(h.sent) != 0 {
				t.Fatal("applied before diff end")
			}
			if !strings.Contains(strings.Join(m.Hints(), " "), "scroll to the end of the diff") {
				t.Fatal(m.Hints())
			}
			for i := 0; m.dialog != nil && !m.dialog.diffSeenEnd && i < 2200; i++ {
				switch how {
				case "end":
					m = press(m, tea.KeyEnd)
				case "pagedown":
					m = press(m, tea.KeyPgDown)
				case "down":
					m = press(m, tea.KeyDown)
				case "wheel":
					m = step(m, tea.MouseWheelMsg{Button: tea.MouseWheelDown})
				}
			}
			if !m.dialog.diffSeenEnd || !strings.Contains(m.View().Content, "+last") {
				t.Fatal("diff end not displayed")
			}
			m = press(m, 'a')
			if len(h.sent) != 1 || h.sent[0]["choice"] != "apply" {
				t.Fatal(h.sent)
			}
		})
	}
}
func TestEditSendsJSONObjectOnly(t *testing.T) {
	for _, invalid := range []string{"[]", "null", "{oops"} {
		m, h := setup()
		m = gate(m, "G3", "")
		m = press(m, 'e')
		m.dialog.input.SetValue(invalid)
		m = press(m, tea.KeyEnter)
		if len(h.sent) != 0 || m.dialog.err == "" {
			t.Fatal("invalid edits accepted")
		}
		m.dialog.input.SetValue(`{"ids":["a"]}`)
		m = press(m, tea.KeyEnter)
		if len(h.sent) != 1 || h.sent[0]["choice"] != "edit" {
			t.Fatal(h.sent)
		}
	}
}
func TestGateResultFromOtherClientClosesOnlyMatchingDialog(t *testing.T) {
	m, h := setup()
	m = gate(m, "G3", "")
	m = step(m, event("gate_result", map[string]any{"request_id": "other", "gate": "G3", "choice": "approve", "person": "web:12345678"}))
	if m.dialog == nil {
		t.Fatal("unrelated result closed gate")
	}
	m = step(m, event("gate_result", map[string]any{"request_id": "req-1", "gate": "G3", "choice": "approve", "person": "web:12345678"}))
	if m.dialog != nil || len(h.sent) != 0 {
		t.Fatal("remote reply mishandled")
	}
}
