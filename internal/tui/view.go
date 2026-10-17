package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func (m Model) footer() string {
	hint := "Tab: next control · Enter: edit or activate · Ctrl+E: review"
	switch {
	case m.menu:
		hint = "Up/Down: choose action · Enter: run · Esc: close"
	case m.editing:
		hint = "Enter/Esc: finish editing · Tab: next · Ctrl+Space: path"
	case m.tab == 1 && m.reviewMode:
		hint = "Up/Down/PgUp/PgDown: scroll · V: details · Ctrl+S: start"
	case m.tab == 0:
		hint = "Up/Down: run · Enter: inspect · Ctrl+T: retry · Ctrl+O: export"
	case m.tab == 2:
		hint = "Up/Down/PgUp/PgDown: scroll · Ctrl+4: findings"
	case m.tab == 3 && m.evidenceFocus:
		hint = "Up/Down/PgUp/PgDown: scroll · V: raw details · Esc: table"
	case m.tab == 3 && m.searching:
		hint = "Type to filter · Enter/Esc: return to findings table"
	case m.tab == 3:
		hint = "Enter: details · /: filter · PgUp/PgDown: result pages"
	case m.tab == 4:
		hint = "Tab: next · Enter: edit/choose · Ctrl+O: export named run"
	}
	global := "Ctrl+K: save key / actions · Ctrl+N: new scan · Ctrl+Q: quit"
	if m.scanning {
		global += " · Ctrl+X: cancel"
	}
	return ansi.Wrap(hint+"\n"+global, max(1, m.width), "")
}
func (m Model) header() string {
	name := "DevSecOps Agent · " + tabs[m.tab]
	if m.tab == 2 && m.activityID != "" {
		name += " · " + m.runLabel(m.activityID)
	}
	title := lipgloss.NewStyle().Bold(true).Render(name)
	navigation := "1 History · 2 Workspace · 3 Activity · 4 Findings · 5 Reports"
	return ansi.Wrap(title+"\n"+navigation, max(1, m.width), "")
}
func (m Model) statusView() string {
	lines := strings.Split(ansi.Wrap(ansi.Strip(m.status), max(1, m.width), ""), "\n")
	if len(lines) > 2 {
		lines = lines[:2]
		lines[1] = ansi.Truncate(lines[1], max(1, m.width)-1, "") + "…"
	}
	return strings.Join(lines, "\n")
}
func (m Model) bodyHeight() int {
	return max(1, m.height-lipgloss.Height(m.header())-lipgloss.Height(m.footer())-lipgloss.Height(m.statusView())-2)
}
func (m *Model) resize() {
	width, height := max(1, m.width), m.bodyHeight()
	if m.layoutWidth != width {
		m.layoutWidth = width
		m.historyTable.SetWidth(width)
		m.findingTable.SetWidth(width)
		m.historyTable.SetColumns([]table.Column{{Title: "ID", Width: 4}, {Title: "Run", Width: max(5, width-51)}, {Title: "Status", Width: 12}, {Title: "Try", Width: 5}, {Title: "Started", Width: 20}})
		m.findingTable.SetColumns([]table.Column{{Title: "Severity", Width: 8}, {Title: "CWE", Width: 9}, {Title: "Status", Width: 12}, {Title: "Scanner", Width: 12}, {Title: "Title", Width: max(5, width-51)}})
		m.search.SetWidth(max(1, width-2))
		for i := range m.inputs {
			m.inputs[i].SetWidth(max(1, width-4))
		}
	}
	if target := max(1, height-lipgloss.Height(ansi.Wrap(m.availability, width, ""))-2); m.historyTable.Height()+1 != target {
		m.historyTable.SetHeight(target)
	}
	if target := max(1, height-4); m.findingTable.Height()+1 != target {
		m.findingTable.SetHeight(target)
	}
	m.form.SetWidth(width)
	m.form.SetHeight(height)
	m.review.SetWidth(width)
	m.review.SetHeight(height)
	m.evidence.SetWidth(width)
	m.evidence.SetHeight(height - 1)
	m.activity.SetWidth(width)
	m.activity.SetHeight(height)
}
func bounded(text string, width, height int) string {
	lines := strings.Split(text, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], max(1, width), "")
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
func (m Model) formView() string {
	lines, focusedLine := []string{}, 0
	for _, control := range m.controls() {
		marker := "  "
		if control == m.field && !m.keyInput {
			marker, focusedLine = "> ", len(lines)
		}
		switch control {
		case advancedControl:
			state := "show"
			if m.advanced {
				state = "hide"
			}
			lines = append(lines, marker+"[Advanced options · "+state+"]")
		case reviewControl:
			lines = append(lines, marker+"[Review checkout and effective settings · Ctrl+E]")
		case startControl:
			label := "Start reviewed scan · Ctrl+S"
			if m.reviewed == nil {
				label = "Start · review the current settings first"
			}
			lines = append(lines, marker+"["+label+"]")
		case exportControl:
			lines = append(lines, marker+"[Export "+m.runLabel(m.target())+" · Ctrl+O]")
		default:
			lines = append(lines, marker+labels[control])
			value := ansi.Strip(m.inputs[control].Value())
			if value == "" {
				value = "(optional)"
			}
			if len(choices[control]) > 0 {
				value += "  [Left/Right or Enter to choose]"
			} else if m.editing && control == m.field {
				value = m.inputs[control].View()
			}
			lines = append(lines, "  "+value)
		}
	}
	if m.tab == 4 {
		lines = append(lines, "", "Export target: "+m.runLabel(m.target()))
	}
	if m.tab == 1 {
		// API keys (values never shown): entry lives on the Workspace tab
		// next to the scan configuration it authorizes. Ctrl+K saves from
		// here (or whenever a key entry is in progress); elsewhere Ctrl+K
		// keeps its newer role as the action menu (see FR71).
		status := m.envStatus
		if status == "" {
			status = "Loading saved keys…"
		}
		lines = append(lines, "", "API keys (values never shown): "+status)
		nameLabel, valueLabel := "  Variable", "  Value (hidden)"
		if m.keyInput && m.keysFocus == 0 {
			nameLabel, focusedLine = "> Variable", len(lines)
		}
		if m.keyInput && m.keysFocus == 1 {
			valueLabel, focusedLine = "> Value (hidden)", len(lines)+2
		}
		lines = append(lines, nameLabel, "  "+m.keysName.View())
		lines = append(lines, valueLabel, "  "+m.keysValue.View())
		lines = append(lines, "  Ctrl+K: save to project .env")
		if len(m.envNames) > 0 {
			lines = append(lines, "", "Stored keys (values never shown):", "  "+strings.Join(m.envNames, "\n  "))
		}
	}
	view := m.form
	view.SetHeight(m.bodyHeight())
	view.SetContent(strings.Join(lines, "\n"))
	if focusedLine < view.YOffset() {
		view.SetYOffset(focusedLine)
	} else if focusedLine+2 >= view.YOffset()+view.Height() {
		view.SetYOffset(focusedLine + 3 - view.Height())
	}
	return view.View()
}
func (m Model) menuView() string {
	lines := []string{"Actions · target: " + m.runLabel(m.target()), ""}
	for i, name := range actionNames {
		marker := "  "
		if i == m.menuCursor {
			marker = "> "
		}
		if (i == 6 || i == 7) && m.target() == "" {
			name += " (choose a run first)"
		}
		lines = append(lines, marker+name)
	}
	view := m.form
	view.SetContent(strings.Join(lines, "\n"))
	view.SetHeight(m.bodyHeight())
	view.SetYOffset(max(0, m.menuCursor+3-view.Height()))
	return view.View()
}
func (m Model) View() tea.View {
	if m.quitModal {
		text := "A scan is active. Cancel it and preserve partial evidence before quitting?\n\nY/Enter: cancel and quit    N/Esc: stay"
		if m.width < 60 || m.height < 18 {
			text = "Active scan.\nY: cancel and quit\nN/Esc: stay"
		}
		v := tea.NewView(bounded(ansi.Wrap(text, max(1, m.width), ""), m.width, max(1, m.height)))
		v.AltScreen = true
		return v
	}
	if m.width < 60 || m.height < 18 {
		text := fmt.Sprintf("Terminal is %dx%d.\nUse at least 60 columns and 18 rows.\nResize to continue; Ctrl+Q quits.", m.width, m.height)
		v := tea.NewView(bounded(ansi.Wrap(text, max(1, m.width), ""), m.width, max(1, m.height)))
		v.AltScreen = true
		return v
	}
	height := m.bodyHeight()
	body := ""
	if m.menu {
		body = m.menuView()
	} else {
		switch m.tab {
		case 0:
			availability := ansi.Wrap(m.availability, m.width, "")
			view := m.historyTable
			if target := max(1, height-lipgloss.Height(availability)-2); view.Height()+1 != target {
				view.SetHeight(target)
			}
			if len(m.history) == 0 {
				body = "No saved scans yet.\n\nCtrl+N opens your first scan.\n\n" + availability
			} else {
				body = availability + "\n" + view.View() + "\nTarget: " + m.runLabel(m.target())
			}
		case 1:
			if m.reviewMode {
				view := m.review
				view.SetHeight(height)
				body = view.View()
			} else {
				body = m.formView()
			}
		case 2:
			view := m.activity
			view.SetHeight(height)
			body = view.View()
		case 3:
			if m.evidenceFocus {
				view := m.evidence
				view.SetHeight(max(1, height-1))
				body = "Finding details · " + m.runLabel(m.selected) + "\n" + view.View()
			} else {
				view := m.findingTable
				if target := max(1, height-4); view.Height()+1 != target {
					view.SetHeight(target)
				}
				body = "Findings · " + m.runLabel(m.selected) + "\n" + m.search.View() + "\n" + view.View() + fmt.Sprintf("\n%d–%d of %d", min(m.page.Offset+1, m.page.Total), min(m.page.Offset+200, m.page.Total), m.page.Total)
			}
		case 4:
			body = m.formView()
		}
	}
	v := tea.NewView(m.header() + "\n\n" + bounded(body, m.width, height) + "\n\n" + m.statusView() + "\n" + m.footer())
	v.AltScreen = true
	return v
}
