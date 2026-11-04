package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/service"
)

type notificationPanel struct {
	mode     string
	busy     bool
	cursor   int
	settings service.NotificationSettings
	receipt  service.NotificationResponse
	selected map[string]bool
}
type notificationRow struct {
	key, label string
	checked    bool
	action     bool
}

var notificationEvents = []service.NotificationEvent{
	{Kind: "scan_completed", Label: "Scan completed"}, {Kind: "scan_failed", Label: "Scan failed/interrupted"},
	{Kind: "scan_cancelled", Label: "Scan cancelled"}, {Kind: "gate_failed", Label: "Security gate failed"},
	{Kind: "high_critical_findings", Label: "High/Critical findings"}, {Kind: "ai_failed", Label: "AI unavailable/failed"},
	{Kind: "report_ready", Label: "Reports ready"},
}

func includes(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func (m Model) notificationRows() []notificationRow {
	p := m.notificationPanel
	if p == nil {
		return nil
	}
	rows := []notificationRow{}
	if p.mode == "settings" {
		rows = append(rows, notificationRow{key: "mode", label: "Mode: " + p.settings.Mode, action: true})
		for _, channel := range []string{"telegram", "discord"} {
			config := p.settings.Telegram
			if channel == "discord" {
				config = p.settings.Discord
			}
			rows = append(rows, notificationRow{key: channel, label: channel + " enabled", checked: config.Enabled})
			for _, event := range notificationEvents {
				rows = append(rows, notificationRow{key: channel + ":" + event.Kind, label: channel + ": " + event.Label, checked: includes(config.Events, event.Kind)})
			}
		}
		return append(rows, notificationRow{key: "save", label: "Save notification preferences", action: true})
	}
	events := map[string]bool{}
	for _, delivery := range p.receipt.Deliveries {
		if delivery.Status != "pending" {
			continue
		}
		key := "channel:" + delivery.Channel
		rows = append(rows, notificationRow{key: key, label: "Send to " + delivery.Channel, checked: p.selected[key]})
		for _, event := range delivery.Events {
			events[event.Kind] = true
		}
	}
	for _, event := range notificationEvents {
		if events[event.Kind] {
			rows = append(rows, notificationRow{key: event.Kind, label: event.Label, checked: p.selected[event.Kind]})
		}
	}
	return append(rows, notificationRow{key: "send", label: "Send selected summaries now", action: true})
}
func (m Model) notificationCmd(params map[string]any) tea.Cmd {
	api, panel := m.api, m.notificationPanel
	return func() tea.Msg {
		result, err := api.Notification(context.Background(), params)
		return loaded{kind: "notification", id: fmt.Sprint(params["action"]), value: notificationLoaded{panel: panel, result: result}, err: err}
	}
}

type notificationLoaded struct {
	panel  *notificationPanel
	result service.NotificationResponse
}

func (m *Model) notificationLoaded(msg loaded) {
	loaded := msg.value.(notificationLoaded)
	if m.notificationPanel != loaded.panel || loaded.panel == nil {
		return
	}
	p := m.notificationPanel
	p.busy = false
	if msg.err != nil {
		m.status = "Notification operation failed; check configuration and retained receipts."
		return
	}
	if loaded.result.Settings != nil {
		p.settings = *loaded.result.Settings
	}
	if msg.id == "deliveries" || msg.id == "send" {
		p.receipt = loaded.result
		p.selected = map[string]bool{}
		p.cursor = 0
	}
	if msg.id == "save" {
		m.status = "Notification preferences saved. No messages sent."
		m.notificationPanel = nil
	}
	if msg.id == "send" {
		m.status = "Delivery status recorded. Unknown delivery is never retried automatically."
	}
}
func (m Model) notificationKey(key string) (tea.Model, tea.Cmd) {
	p := m.notificationPanel
	if key == "esc" {
		m.notificationPanel = nil
		return m, nil
	}
	if p.busy {
		return m, nil
	}
	rows := m.notificationRows()
	switch key {
	case "up":
		p.cursor = (p.cursor + len(rows) - 1) % len(rows)
	case "down":
		p.cursor = (p.cursor + 1) % len(rows)
	case "enter", "space", "left", "right":
		row := rows[p.cursor]
		if row.key == "save" {
			if key != "enter" {
				return m, nil
			}
			p.busy = true
			return m, m.notificationCmd(map[string]any{"action": "save", "settings": p.settings})
		}
		if row.key == "send" {
			if key != "enter" {
				return m, nil
			}
			events, channels := []string{}, []string{}
			for _, event := range notificationEvents {
				if p.selected[event.Kind] {
					events = append(events, event.Kind)
				}
			}
			for _, channel := range []string{"telegram", "discord"} {
				if p.selected["channel:"+channel] {
					channels = append(channels, channel)
				}
			}
			if len(events) == 0 || len(channels) == 0 {
				m.status = "Choose events and destinations before sending."
				return m, nil
			}
			p.busy = true
			return m, m.notificationCmd(map[string]any{"action": "send", "run_id": p.receipt.RunID, "events": events, "channels": channels})
		}
		if p.mode == "settings" {
			if row.key == "mode" {
				if p.settings.Mode == "manual" {
					p.settings.Mode = "automatic"
				} else {
					p.settings.Mode = "manual"
				}
				return m, nil
			}
			parts := strings.SplitN(row.key, ":", 2)
			channel := &p.settings.Telegram
			if parts[0] == "discord" {
				channel = &p.settings.Discord
			}
			if len(parts) == 1 {
				channel.Enabled = !channel.Enabled
			} else {
				values := []string{}
				found := false
				for _, value := range channel.Events {
					if value == parts[1] {
						found = true
					} else {
						values = append(values, value)
					}
				}
				if !found {
					values = append(values, parts[1])
				}
				channel.Events = values
			}
		} else {
			p.selected[row.key] = !p.selected[row.key]
		}
	}
	return m, nil
}
func (m Model) notificationView(height int) string {
	p := m.notificationPanel
	title := "Notifications · choose what to send"
	if p.busy {
		return title + "\nWorking…"
	}
	lines := []string{title}
	if p.mode == "settings" {
		lines = append(lines, "manual: ask after scans; automatic: use saved event rules", "Credentials: Workspace Ctrl+K or `notifications configure` help")
	} else {
		for _, delivery := range p.receipt.Deliveries {
			lines = append(lines, delivery.Channel+": "+delivery.Status+" · "+delivery.Detail)
		}
		if len(p.receipt.Deliveries) == 0 {
			lines = append(lines, "No drafts. F6 configures future notifications.")
		}
	}
	header := len(lines)
	rows := m.notificationRows()
	visible := max(1, height-header)
	start := max(0, p.cursor-visible+1)
	for index := start; index < min(len(rows), start+visible); index++ {
		row := rows[index]
		marker := "  "
		if index == p.cursor {
			marker = "> "
		}
		checkbox := "[ ] "
		if row.checked {
			checkbox = "[x] "
		}
		if row.action {
			checkbox = ""
		}
		lines = append(lines, marker+checkbox+row.label)
	}
	return strings.Join(lines, "\n")
}
