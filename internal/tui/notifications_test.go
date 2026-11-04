package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/service"
)

type notificationAPI struct {
	fakeAPI
	notifications int
}

func (f *notificationAPI) Notification(_ context.Context, params map[string]any) (service.NotificationResponse, error) {
	f.notifications++
	return service.NotificationResponse{Settings: &service.NotificationSettings{SchemaVersion: 1, Mode: "manual"}}, nil
}

func TestFR75SettingsUseArrowsAndExplicitSave(t *testing.T) {
	api := &notificationAPI{}
	m := New(api)
	m.ready = true
	updated, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyF6})
	m = updated.(Model)
	if cmd == nil || api.notifications != 0 {
		t.Fatal("settings must load asynchronously")
	}
	updated, _ = m.Update(cmd())
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = updated.(Model)
	if !m.notificationPanel.settings.Telegram.Enabled || api.notifications != 1 {
		t.Fatal("toggle must not send or save")
	}
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	m = updated.(Model)
	if m.notificationPanel != nil || api.notifications != 1 {
		t.Fatal("escape must defer without sending")
	}
}

func TestFR75ReviewStartsWithNothingSelectedAndFitsSmallTerminals(t *testing.T) {
	api := &notificationAPI{}
	m := New(api)
	m.ready = true
	m.notificationPanel = &notificationPanel{mode: "review", selected: map[string]bool{}, receipt: service.NotificationResponse{RunID: "run-1", Deliveries: []service.NotificationDelivery{{Channel: "discord", Status: "pending", Events: []service.NotificationEvent{{Kind: "scan_completed", Label: "Scan completed", Message: "Scan run-1 completed."}}}}}}
	m.notificationPanel.cursor = len(m.notificationRows()) - 1
	updated, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = updated.(Model)
	if cmd != nil || api.notifications != 0 || !strings.Contains(m.status, "Choose") {
		t.Fatal("empty choices must not send")
	}
	for _, size := range [][2]int{{80, 24}, {75, 26}, {59, 17}} {
		updated, _ = m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = updated.(Model)
		if lines := strings.Count(m.View().Content, "\n") + 1; lines > size[1] {
			t.Fatalf("view exceeds %v: %d", size, lines)
		}
	}
}
