package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

type credentialAPI struct {
	fakeAPI
	savedName, savedValue string
	saves                 int
}

func (f *credentialAPI) EnvSet(_ context.Context, name, value string) error {
	f.savedName, f.savedValue = name, value
	f.saves++
	return nil
}

func typeCredential(m Model, value string) Model {
	for _, code := range value {
		m, _ = keyState(m, tea.KeyPressMsg{Code: code, Text: string(code)})
	}
	return m
}

func TestFR71CredentialDigitsStayInActiveField(t *testing.T) {
	m := New(&fakeAPI{})
	m.ready = true
	m, _ = keyState(m, ctrl('n'))
	m, _ = keyState(m, ctrl('k'))
	if m.editing || m.inputs[0].Focused() || !m.keysName.Focused() {
		t.Fatal("credential entry did not take focus from checkout editing")
	}
	name := "TEST12345_API_KEY"
	m = typeCredential(m, name)
	if m.tab != 1 || !m.keyInput || m.keysName.Value() != name {
		t.Fatal("digits in the variable name activated navigation")
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyTab})
	value := "abc1def2345"
	m = typeCredential(m, value)
	if m.tab != 1 || !m.keyInput || m.keysValue.Value() != value {
		t.Fatal("digits in the hidden value activated navigation or truncated input")
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.keyInput || m.keysName.Focused() || m.keysValue.Focused() {
		t.Fatal("Escape retained credential capture or widget focus")
	}
	m, _ = keyState(m, tea.KeyPressMsg{Code: '1', Text: "1"})
	if m.tab != 0 {
		t.Fatal("numeric navigation did not resume after leaving credential entry")
	}
}

func TestFR71NavigationReleasesCredentialCapture(t *testing.T) {
	for _, focus := range []int{0, 1} {
		for _, destination := range []rune{'n', '1', '2', '3', '4', '5', 'e'} {
			t.Run(fmt.Sprintf("field%d/ctrl+%c", focus, destination), func(t *testing.T) {
				m := New(&fakeAPI{})
				m.ready = true
				m, _ = keyState(m, ctrl('k'))
				m = typeCredential(m, "TEST_API_KEY")
				if focus == 1 {
					m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyTab})
					m = typeCredential(m, "dummy-secret")
				}
				name, value := m.keysName.Value(), m.keysValue.Value()
				m, _ = keyState(m, ctrl(destination))
				if m.keyInput || m.keysName.Focused() || m.keysValue.Focused() {
					t.Fatal("navigation retained credential capture or widget focus")
				}
				checkout := m.inputs[0].Value()
				m = typeCredential(m, "Z")
				if m.keysName.Value() != name || m.keysValue.Value() != value {
					t.Fatal("typing after navigation modified a hidden credential")
				}
				if destination == 'n' && (!m.editing || !m.inputs[0].Focused() || m.inputs[0].Value() != checkout+"Z") {
					t.Fatal("New scan did not route typing to the checkout")
				}
			})
		}
	}
}

func TestFR71QR12SaveShortcutDuringCredentialEntry(t *testing.T) {
	api := &credentialAPI{}
	m := New(api)
	m.ready = true
	m, _ = keyState(m, ctrl('k'))
	m = typeCredential(m, "TEST_API_KEY")
	m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyTab})
	value := "dummy-secret"
	m = typeCredential(m, value)
	if strings.Contains(m.View().Content, value) {
		t.Fatal("the active credential value was visible")
	}
	m, cmd := keyState(m, ctrl('k'))
	if cmd == nil {
		t.Fatal("the advertised shortcut did not produce a save command during entry")
	}
	if api.saves != 0 || api.calls != 0 {
		t.Fatal("saving performed service work in the UI update loop")
	}
	if m.keysValue.Value() != "" {
		t.Fatal("saving retained the secret in the value widget")
	}
	m = deliver(m, cmd)
	if api.saves != 1 || api.savedName != "TEST_API_KEY" || api.savedValue != value {
		t.Fatal("the save command did not pass the complete credential to EnvSet once")
	}
	if len(m.envNames) != 1 || m.envNames[0] != "MISTRAL_API_KEY" {
		t.Fatal("saving did not refresh the stored key names")
	}
	if strings.Contains(m.View().Content, value) {
		t.Fatal("saving exposed the credential value")
	}
}

func TestQR21ActiveCredentialControlsRemainVisible(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {75, 26}, {60, 20}, {60, 18}, {120, 40}} {
		for _, advanced := range []bool{false, true} {
			t.Run(fmt.Sprintf("%dx%d/advanced=%t", size[0], size[1], advanced), func(t *testing.T) {
				m := New(&fakeAPI{})
				m.ready, m.advanced = true, advanced
				updated, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
				m = updated.(Model)
				m, _ = keyState(m, ctrl('k'))
				m = typeCredential(m, "TEST_API_KEY")
				for _, label := range []string{"> Variable", "> Value (hidden)", "> Variable"} {
					text := ansi.Strip(m.View().Content)
					lines := strings.Split(text, "\n")
					found := false
					for i, line := range lines {
						if strings.Contains(line, label) {
							found = i+1 < len(lines) && strings.TrimSpace(lines[i+1]) != ""
						}
					}
					if !found {
						t.Fatalf("the active %s label and input were not visible", label)
					}
					if len(lines) > size[1] {
						t.Fatal("credential entry exceeded the terminal height")
					}
					for _, line := range lines {
						if ansi.StringWidth(line) > size[0] {
							t.Fatal("credential entry exceeded the terminal width")
						}
					}
					m, _ = keyState(m, tea.KeyPressMsg{Code: tea.KeyTab})
				}
			})
		}
	}
}
