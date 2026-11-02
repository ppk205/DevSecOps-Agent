package chat

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
	"github.com/charmbracelet/x/ansi"
)

type fakeHost struct {
	events chan bridge.ChatEvent
	sent   []bridge.ChatMessage
	closed bool
}

func (f *fakeHost) Events() <-chan bridge.ChatEvent { return f.events }
func (f *fakeHost) Send(m bridge.ChatMessage) error { f.sent = append(f.sent, m); return nil }
func (f *fakeHost) Close()                          { f.closed = true }
func (f *fakeHost) Err() error                      { return errors.New("host disconnected") }
func setup() (Model, *fakeHost) {
	h := &fakeHost{events: make(chan bridge.ChatEvent)}
	return New(h, nil), h
}
func step(m Model, msg tea.Msg) Model { next, _ := m.Update(msg); return next.(Model) }
func press(m Model, code rune) Model  { return step(m, tea.KeyPressMsg{Code: code}) }
func event(kind string, fields map[string]any) bridge.ChatEvent {
	fields["type"], fields["seq"], fields["protocol"] = kind, 1, bridge.ChatProtocol
	b, _ := json.Marshal(fields)
	return bridge.ChatEvent{Type: kind, Seq: 1, Raw: b}
}
func gate(m Model, g, diff string) Model {
	return step(m, event("permission_request", map[string]any{"request_id": "req-1", "gate": g, "title": "Review", "detail": "Review code", "payload": map[string]any{"diff": diff}, "mode": "ask", "ai_recommendation": "Inspect evidence"}))
}
func click(m Model, action string) Model {
	_, hits := m.render()
	for _, h := range hits {
		if h.action == action {
			return step(m, tea.MouseClickMsg{X: h.x, Y: h.y, Button: tea.MouseLeft})
		}
	}
	panic("missing clickable action: " + action)
}

func TestHintsPerState(t *testing.T) {
	m, _ := setup()
	m.screen = chatScreen
	if !reflect.DeepEqual(m.Hints(), []string{"Enter send", "/ commands", "Esc stop", "? help"}) {
		t.Fatal(m.Hints())
	}
	m.busy = true
	if !reflect.DeepEqual(m.Hints(), []string{"Esc stop", "? help"}) {
		t.Fatal(m.Hints())
	}
}
func TestSlashOpensFilterableMenu(t *testing.T) {
	m, h := setup()
	m.screen = chatScreen
	m.input.SetValue("/mo")
	if got := m.filteredMenu(); len(got) != 2 || got[0].name != "model" || got[1].name != "mode" {
		t.Fatal(got)
	}
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 1 || h.sent[0]["name"] != "model" {
		t.Fatal(h.sent)
	}
}
func TestToolBlocksCollapseAndExpandByClick(t *testing.T) {
	m, _ := setup()
	m.screen = chatScreen
	m = step(m, event("tool_call", map[string]any{"id": "a", "name": "read_file", "arguments": map[string]any{"path": "Sample.java"}}))
	if strings.Contains(m.View().Content, "Sample.java") {
		t.Fatal("block starts expanded")
	}
	m = click(m, "block:0")
	if !strings.Contains(m.View().Content, "Sample.java") {
		t.Fatal("block did not expand")
	}
	m = click(m, "block:0")
	if strings.Contains(m.View().Content, "Sample.java") {
		t.Fatal("block did not collapse")
	}
}
func TestTabsClickable(t *testing.T) {
	m, _ := setup()
	m = click(m, "tab:1")
	if m.tab != tabBaseline {
		t.Fatal("baseline tab not selected")
	}
	m = press(m, tea.KeyEscape)
	if m.tab != tabChat {
		t.Fatal("Esc did not return to chat")
	}
}
func TestBrokenPipeLeavesGateUndecided(t *testing.T) {
	m, h := setup()
	m = gate(m, "G6", "+fix")
	close(h.events)
	m = step(m, listen(h, 0)())
	if m.dialog != nil || !m.disconnected || !strings.Contains(strings.Join(m.Hints(), " "), "r restart") {
		t.Fatal("missing disconnect state")
	}
	m.input.SetValue("do work")
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 0 {
		t.Fatal("disconnect sent a reply or message")
	}
}
func TestRestartUsesSessionPath(t *testing.T) {
	m, h := setup()
	replacement := &fakeHost{events: make(chan bridge.ChatEvent)}
	m.Restart = func() (Host, error) { return replacement, nil }
	m = step(m, event("ready", map[string]any{"target": "project", "provider": "local", "model": "model", "mode": "ask", "session_path": ".devsec/sessions/s.jsonl"}))
	m = step(m, disconnectedMsg{generation: 0})
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'r'})
	if cmd == nil {
		t.Fatal("restart has no command")
	}
	m = step(m, cmd())
	if !h.closed || m.host != replacement || m.disconnected {
		t.Fatal("host not replaced")
	}
	if len(replacement.sent) != 2 || replacement.sent[1]["type"] != "start" || replacement.sent[1]["resume"] != ".devsec/sessions/s.jsonl" {
		t.Fatal(replacement.sent)
	}
}
func TestLayouts(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {75, 26}, {59, 17}} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			m, _ := setup()
			m = step(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			for _, screen := range []int{startScreen, chatScreen} {
				m.screen = screen
				view := m.View()
				if lines := strings.Split(view.Content, "\n"); len(lines) != size[1] {
					t.Fatalf("height=%d", len(lines))
				}
				for _, line := range strings.Split(view.Content, "\n") {
					if ansi.StringWidth(line) > size[0] {
						t.Fatal("line overflows")
					}
				}
				if size[0] < 60 && !strings.Contains(view.Content, "Resize") {
					t.Fatal("missing resize hint")
				}
				if view.MouseMode != tea.MouseModeCellMotion {
					t.Fatal("mouse is disabled")
				}
			}
		})
	}
}
func TestRemoteCommandShowsURL(t *testing.T) {
	m, h := setup()
	m.screen = chatScreen
	m.input.SetValue("/remote on")
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 1 || h.sent[0]["name"] != "remote" || !reflect.DeepEqual(h.sent[0]["args"], []string{"on"}) {
		t.Fatal(h.sent)
	}
	m = step(m, event("remote", map[string]any{"url": "http://127.0.0.1:8765/app/remote#t=fixture"}))
	if !strings.Contains(m.View().Content, "#t=fixture") || !strings.Contains(m.View().Content, "copy") {
		t.Fatal(m.View().Content)
	}
	m.input.SetValue("/remote off")
	m = press(m, tea.KeyEnter)
	if !reflect.DeepEqual(h.sent[1]["args"], []string{"off"}) {
		t.Fatal(h.sent)
	}
}
func TestBannerButtons(t *testing.T) {
	for _, action := range []string{"review", "dismiss"} {
		m, h := setup()
		m.screen = chatScreen
		m = step(m, event("pending", map[string]any{"items": []map[string]any{{"id": "p1", "ref": "abc123", "files": []string{"A.java"}}}}))
		if !strings.Contains(m.View().Content, "abc123") {
			t.Fatal("banner absent")
		}
		m = click(m, "pending:"+action+":p1")
		if len(h.sent) != 1 || h.sent[0]["name"] != "pending" || !reflect.DeepEqual(h.sent[0]["args"], []string{action, "p1"}) {
			t.Fatal(h.sent)
		}
	}
}
func TestModeAutoNeedsExplicitConfirmation(t *testing.T) {
	m, h := setup()
	m.screen = chatScreen
	m.input.SetValue("/mode auto")
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 0 || !m.confirmAuto {
		t.Fatal("auto sent without confirmation")
	}
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 0 {
		t.Fatal("Enter confirmed auto")
	}
	m = press(m, 'y')
	if len(h.sent) != 1 {
		t.Fatal("explicit confirmation not relayed")
	}
}
