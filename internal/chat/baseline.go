package chat

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
)

// Implemented by tui.Model; comparison data never traverses the chat pipe.
type baselineSource interface {
	ComparisonFindings(context.Context) ([]map[string]string, error)
}
type comparisonMsg struct {
	findings []Finding
	err      error
}

func (m *Model) updateComparison() {
	if m.comparing && m.baselineFindings != nil {
		c := Compare(m.harnessFindings, m.baselineFindings)
		m.comparison = &c
	}
}
func (m Model) baselineAction(action string) (tea.Model, tea.Cmd) {
	if action == "compare" {
		source, ok := m.baseline.(baselineSource)
		if !ok {
			m.notice = "Select a baseline run first."
			return m, nil
		}
		m.comparing = true
		m.comparison = nil
		m.baselineFindings = nil
		m.send(bridge.ChatMessage{"type": "command", "name": "findings", "args": []string{}})
		return m, func() tea.Msg {
			rows, err := source.ComparisonFindings(context.Background())
			findings := make([]Finding, 0, len(rows))
			for _, row := range rows {
				findings = append(findings, Finding{row["file"], row["cwe"]})
			}
			return comparisonMsg{findings, err}
		}
	}
	if m.baseline != nil {
		key := 'n'
		if action == "history" {
			key = '1'
		}
		var cmd tea.Cmd
		m.baseline, cmd = m.baseline.Update(tea.KeyPressMsg{Code: key, Mod: tea.ModCtrl})
		return m, cmd
	}
	return m, nil
}
func (m Model) baselineView() *canvas {
	c := newCanvas(m.width, m.bodyHeight())
	c.put(0, "Baseline comparison (testing only)")
	c.buttons(1, [2]string{"[ Run baseline scan ]", "baseline:run"}, [2]string{"[ Compare with this session ]", "baseline:compare"}, [2]string{"[ History ]", "baseline:history"})
	start := 3
	if m.comparison != nil {
		c.put(2, fmt.Sprintf("Harness-only %d · Baseline-only %d · Both %d (counts)", len(m.comparison.HarnessOnly), len(m.comparison.BaselineOnly), len(m.comparison.Both)))
	}
	if m.baseline != nil {
		for y, line := range strings.Split(m.baseline.View().Content, "\n") {
			if y+start < c.height {
				c.put(y+start, line)
			}
		}
	}
	return c
}
