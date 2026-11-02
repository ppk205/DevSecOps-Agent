package tui

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// ComparisonFindings returns file/CWE pairs from the selected baseline run.
// It is called in a command, never from View, and never receives harness data.
func (m Model) ComparisonFindings(ctx context.Context) ([]map[string]string, error) {
	id := m.target()
	if !m.ready || id == "" {
		return nil, errors.New("select a saved baseline run in History")
	}
	rows := []map[string]string{}
	for offset := 0; ; {
		page, err := m.api.Findings(ctx, id, "", offset)
		if err != nil {
			return nil, err
		}
		for _, summary := range page.Items {
			raw, err := m.api.Finding(ctx, id, summary.FindingID)
			if err != nil {
				return nil, err
			}
			var detail struct {
				Observations []struct {
					Location struct {
						File string `json:"file_path"`
					} `json:"location"`
				} `json:"observations"`
			}
			if err = json.Unmarshal(raw, &detail); err != nil {
				return nil, err
			}
			for _, observation := range detail.Observations {
				if observation.Location.File != "" {
					rows = append(rows, map[string]string{"file": observation.Location.File, "cwe": summary.CWE})
				}
			}
		}
		offset += len(page.Items)
		if offset >= page.Total || len(page.Items) == 0 {
			return rows, nil
		}
	}
}

func (m Model) embeddedMouse(msg tea.MouseClickMsg) (tea.Model, tea.Cmd) {
	if msg.Button != tea.MouseLeft || !m.ready {
		return m, nil
	}
	if m.menu {
		index := msg.Y - 2 + max(0, m.menuCursor+3-m.bodyHeight())
		if index >= 0 && index < len(actionNames) {
			m.menuCursor = index
			return m.handleKey(tea.KeyPressMsg{Code: tea.KeyEnter})
		}
		return m, nil
	}
	lines := strings.Split(m.View().Content, "\n")
	if msg.Y < 0 || msg.Y >= len(lines) {
		return m, nil
	}
	line := strings.TrimSpace(ansi.Strip(lines[msg.Y]))
	if m.tab == 0 {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			if id, err := strconv.Atoi(fields[0]); err == nil {
				for i, run := range m.history {
					if run.ID == id {
						m.historyTable.SetCursor(i)
						return m.handleKey(tea.KeyPressMsg{Code: tea.KeyEnter})
					}
				}
			}
		}
	}
	if (m.tab == 1 || m.tab == 4) && !m.reviewMode {
		for _, control := range m.controls() {
			label := ""
			switch control {
			case advancedControl:
				label = "[Advanced options"
			case reviewControl:
				label = "[Review checkout"
			case startControl:
				label = "[Start"
			case exportControl:
				label = "[Export"
			default:
				label = labels[control]
			}
			matched := strings.Contains(line, label)
			if control >= 0 && msg.Y > 0 {
				matched = matched || strings.HasSuffix(strings.TrimSpace(ansi.Strip(lines[msg.Y-1])), label)
			}
			if !matched {
				continue
			}
			m.field = control
			if control >= 0 && len(choices[control]) == 0 {
				m.editing = true
				return m, m.inputs[control].Focus()
			}
			return m.handleKey(tea.KeyPressMsg{Code: tea.KeyEnter})
		}
	}
	return m, nil
}
