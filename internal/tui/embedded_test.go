package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestNewEmbeddedHidesOwnedHeaderAndKeyVariables(t *testing.T) {
	m := NewEmbedded(&fakeAPI{})
	view := m.View().Content
	if strings.Contains(view, "1 History · 2 Workspace") || strings.Contains(view, "Variable") || strings.Contains(view, "MISTRAL_API_KEY") {
		t.Fatal("embedded baseline leaked outer navigation or legacy keys")
	}
	if m.header() != "" {
		t.Fatal("embedded header not hidden")
	}
}

func TestEmbeddedMouseFocusesCheckoutAndActionMenu(t *testing.T) {
	m := NewEmbedded(&fakeAPI{})
	m.ready = true
	for y, line := range strings.Split(m.View().Content, "\n") {
		if strings.Contains(ansi.Strip(line), "Checkout") {
			next, _ := m.Update(tea.MouseClickMsg{Y: y, Button: tea.MouseLeft})
			m = next.(Model)
			break
		}
	}
	if !m.editing || m.field != 0 {
		t.Fatal("mouse did not focus checkout")
	}
	m.menu = true
	m.menuCursor = 0
	next, _ := m.Update(tea.MouseClickMsg{Y: 3, Button: tea.MouseLeft})
	m = next.(Model)
	if m.menu || m.tab != 0 {
		t.Fatal("mouse did not activate History menu action")
	}
}
