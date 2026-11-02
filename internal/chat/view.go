package chat

import (
	"fmt"
	"strings"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type hit struct {
	x, y, width int
	action      string
}
type canvas struct {
	width, height int
	lines         []string
	hits          []hit
}

func newCanvas(width, height int) *canvas {
	return &canvas{width: width, height: height, lines: make([]string, max(0, height))}
}
func (c *canvas) put(y int, text string) {
	if y >= 0 && y < len(c.lines) {
		c.lines[y] = ansi.Truncate(text, max(1, c.width), "")
		kept := c.hits[:0]
		for _, h := range c.hits {
			if h.y != y {
				kept = append(kept, h)
			}
		}
		c.hits = kept
	}
}
func (c *canvas) action(y int, text, action string) {
	c.put(y, text)
	c.hits = append(c.hits, hit{0, y, min(c.width, ansi.StringWidth(text)), action})
}
func (c *canvas) buttons(y int, buttons ...[2]string) {
	x := 0
	for _, b := range buttons {
		w := ansi.StringWidth(b[0])
		if x+w > c.width {
			y++
			x = 0
		}
		if y < 0 || y >= len(c.lines) {
			return
		}
		c.lines[y] += b[0] + " "
		c.hits = append(c.hits, hit{x, y, w, b[1]})
		x += w + 1
	}
}
func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || r == 0x202e || r == 0x202d {
			return -1
		}
		return r
	}, ansi.Strip(s))
}
func wrap(text string, width int) []string {
	return strings.Split(ansi.Hardwrap(strings.ReplaceAll(safeText(text), "\t", "    "), max(1, width), true), "\n")
}
func (m Model) bodyHeight() int { return max(1, m.height-4) }
func (m Model) render() (string, []hit) {
	c := newCanvas(m.width, m.height)
	if m.width < 60 || m.height < 18 {
		for y, line := range wrap("Resize to at least 60 columns and 18 rows.\nCtrl+C twice quits.", m.width) {
			c.put(y, line)
		}
		return strings.Join(c.lines, "\n"), nil
	}
	c.put(0, "DevSecOps Agent · AI hỗ trợ · human decisions")
	labels := []string{"Chat", "Baseline", "Keys"}
	tabs := [][2]string{}
	for i, label := range labels {
		if i == m.tab {
			label = "[ " + label + " ]"
		}
		tabs = append(tabs, [2]string{label, fmt.Sprintf("tab:%d", i)})
	}
	c.buttons(1, tabs...)
	body := m.renderBody()
	for y, line := range body.lines {
		c.put(y+2, line)
	}
	for _, h := range body.hits {
		h.y += 2
		c.hits = append(c.hits, h)
	}
	c.put(m.height-2, safeText(m.statusLine()))
	hints := m.Hints()
	visible := []string{}
	for _, hint := range hints {
		if hint == "? help" {
			continue
		}
		candidate := strings.Join(append(append([]string{}, visible...), hint, "? help"), " · ")
		if ansi.StringWidth(candidate) <= m.width {
			visible = append(visible, hint)
		}
	}
	visible = append(visible, "? help")
	line := strings.Join(visible, " · ")
	c.put(m.height-1, line)
	c.hits = append(c.hits, hit{x: max(0, ansi.StringWidth(line)-6), y: m.height - 1, width: 6, action: "help"})
	return strings.Join(c.lines, "\n"), c.hits
}
func (m Model) View() tea.View {
	content, _ := m.render()
	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.ReportFocus = true
	return v
}
func (m Model) renderBody() *canvas {
	c := newCanvas(m.width, m.bodyHeight())
	if m.disconnected {
		c.put(0, "Host disconnected · pending steps are undecided")
		c.action(2, "[ r Restart session ]", "restart")
		c.put(4, m.notice)
		return c
	}
	if m.dialog != nil {
		return m.dialogView()
	}
	if m.form != nil {
		return m.formView()
	}
	if m.confirmAuto {
		c.put(0, "Switch to auto mode?")
		c.put(2, "Routine gates may be automatic. G5 and G6 stay human decisions.")
		c.put(3, "Local G0 may be automatic while a human client is attached.")
		c.buttons(5, [2]string{"[ y Confirm auto ]", "auto:yes"}, [2]string{"[ n Cancel ]", "auto:no"})
		return c
	}
	if m.help {
		c.put(0, "Help · Ctrl+1 Chat · Ctrl+2 Baseline · Ctrl+3 Keys")
		for i, item := range commandMenu {
			c.put(i+2, "/"+item.name+" — "+item.description)
		}
		c.put(c.height-3, "Gates: letter / click / arrows then Enter. No initial selection.")
		c.put(c.height-2, "G6: scroll the complete diff. Esc leaves the gate undecided.")
		c.action(c.height-1, "[ Close help ]", "help:close")
		return c
	}
	if m.tab == tabKeys {
		return m.keysView()
	}
	if m.tab == tabBaseline {
		return m.baselineView()
	}
	if m.screen == startScreen {
		return m.startView()
	}
	if m.menuOpen() {
		c.put(0, "Commands · type to filter")
		items := m.filteredMenu()
		start := max(0, m.menuIndex-(c.height-5))
		for i := start; i < len(items) && i-start < c.height-4; i++ {
			prefix := "  "
			if i == m.menuIndex {
				prefix = "> "
			}
			c.action(i-start+1, prefix+"/"+items[i].name+" — "+items[i].description, "command:"+items[i].name)
		}
		c.put(c.height-2, m.input.View())
		return c
	}
	base := 0
	if len(m.pending) > 0 {
		m.pendingBanner(c, 0, m.pending[0])
		base = 2
	}
	lines, hits := m.transcriptLines()
	h := m.transcriptHeight()
	offset := min(m.offset, max(0, len(lines)-h))
	for y := 0; y < h && offset+y < len(lines); y++ {
		c.put(y+base, lines[offset+y])
	}
	for _, hit := range hits {
		if hit.y >= offset && hit.y < offset+h {
			hit.y = hit.y - offset + base
			c.hits = append(c.hits, hit)
		}
	}
	c.put(c.height-3, safeText(m.notice))
	if m.busy {
		c.put(c.height-2, "AI support is working…")
	} else {
		c.action(c.height-2, "› "+m.input.View(), "input")
		c.action(c.height-1, "[ Send ]", "send")
	}
	return c
}
func (m Model) dialogView() *canvas {
	d := m.dialog
	c := newCanvas(m.width, m.bodyHeight())
	title := d.gate + " · " + safeText(d.title)
	if d.gate == "G0" || d.gate == "G6" {
		title = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true).Render("DANGEROUS · " + title)
	}
	c.put(0, title)
	c.put(1, "Mode: "+safeText(d.mode)+" · "+fmt.Sprintf("lines %d–%d of %d", d.offset+1, min(len(d.lines), d.offset+d.height), len(d.lines)))
	for y := 0; y < d.height && d.offset+y < len(d.lines); y++ {
		c.put(y+2, d.lines[d.offset+y])
	}
	if d.form != "" {
		label := "Rejection reason"
		if d.form == "edits" {
			label = "Edit payload (JSON object)"
		}
		c.put(c.height-3, label+": "+d.input.View())
		c.put(c.height-2, d.err)
		c.action(c.height-1, "[ Submit ]  Esc: back", "dialog:submit")
		return c
	}
	buttons := [][2]string{}
	for i, b := range d.buttons {
		label := "[ " + b.key + " " + b.label + " ]"
		if i == d.highlight {
			label = ">" + label
		}
		if d.gate == "G6" && !d.diffSeenEnd {
			label = lipgloss.NewStyle().Foreground(lipgloss.Color("242")).Render(label)
		}
		buttons = append(buttons, [2]string{label, "gate:" + b.choice})
	}
	c.buttons(c.height-3, buttons...)
	if d.gate == "G6" && !d.diffSeenEnd {
		c.put(c.height-1, "Scroll to the end of the diff before answering.")
	} else {
		c.put(c.height-1, "No default choice · Esc leaves undecided")
	}
	return c
}
func (m Model) startView() *canvas {
	c := newCanvas(m.width, m.bodyHeight())
	c.put(0, "Start a harness session")
	mark := func(i int) string {
		if i == m.startFocus {
			return "> "
		}
		return "  "
	}
	c.action(2, mark(0)+"Target: "+m.target.View(), "start:target")
	model := "No models added"
	if m.selectedModel() != nil {
		model = m.modelSpec()
	}
	c.action(4, mark(1)+"Model: "+model+"  [ ←/→ choose ]", "start:model")
	if entry := m.selectedModel(); entry != nil {
		c.put(5, "  "+safeText(modelLabel(*entry)))
		if !entry.Local && !entry.KeySet {
			c.action(6, "[ Set key ]", "key:"+entry.Alias)
		}
	}
	c.action(7, mark(2)+"Mode: "+m.startMode+"  [ ←/→ choose ]", "start:mode")
	c.action(9, mark(3)+"[ ＋ Add model ]", "model:add")
	label := mark(4) + "[ Start session ]"
	if m.startReason() != "" {
		label = lipgloss.NewStyle().Foreground(lipgloss.Color("242")).Render(label)
	}
	c.action(11, label, "start")
	c.put(12, m.startReason())
	slots := max(1, (c.height-14)/2)
	first := max(0, (m.startFocus-5)/2-slots+1)
	for i := first; i < len(m.pending); i++ {
		p := m.pending[i]
		y := 14 + (i-first)*2
		if y+1 < c.height {
			m.pendingBanner(c, y, p)
		}
	}
	if m.notice != "" {
		c.put(c.height-1, safeText(m.notice))
	}
	return c
}
func (m Model) formView() *canvas {
	f := m.form
	c := newCanvas(m.width, m.bodyHeight())
	title := "Add model"
	labels := []string{"Name", "Template", "Protocol", "Base URL", "Model ids", "Key (masked)"}
	if f.kind == "key" {
		title = "Set key · " + f.alias
		labels = []string{"Key (masked)"}
	}
	c.put(0, title)
	for i, field := range f.fields {
		prefix := "  "
		if i == f.focus {
			prefix = "> "
		}
		value := field.View()
		if field.EchoMode == 1 && field.Value() != "" {
			value = strings.Repeat("•", min(24, len([]rune(field.Value()))))
		}
		c.action(i+2, prefix+labels[i]+": "+value, fmt.Sprintf("form:field:%d", i))
	}
	row := len(f.fields) + 3
	c.buttons(row, [2]string{"[ Save ]", "form:submit"}, [2]string{"[ Cancel ]", "form:cancel"})
	c.put(row+2, f.err)
	if f.kind == "add" {
		c.put(row+3, "Template: ←/→ choose. Model ids: comma-separated.")
		c.put(row+4, "The host validates the model and local/cloud key requirements.")
	}
	return c
}
func (m Model) keysView() *canvas {
	c := newCanvas(m.width, m.bodyHeight())
	c.put(0, "Added models · keys are masked")
	c.action(1, "[ ＋ Add model ]", "model:add")
	rows := max(1, (c.height-3)/3)
	start := max(0, m.keysIndex-rows+1)
	for i := start; i < len(m.models) && i-start < rows; i++ {
		e := m.models[i]
		y := 3 + (i-start)*3
		c.put(y, safeText(modelLabel(e)))
		set, remove := "[ Set key ]", "[ Remove ]"
		if i == m.keysIndex {
			if m.keysAction == 0 {
				set = ">" + set
			} else {
				remove = ">" + remove
			}
		}
		c.buttons(y+1, [2]string{set, "key:" + e.Alias}, [2]string{remove, "remove:" + e.Alias})
	}
	if m.notice != "" {
		c.put(c.height-1, safeText(m.notice))
	}
	return c
}
func (m Model) pendingBanner(c *canvas, y int, p pendingReview) {
	ref := p.Ref
	if ref == "" {
		ref = "folder changes"
	}
	if len(ref) > 12 {
		ref = ref[:12]
	}
	c.put(y, fmt.Sprintf("New commit %s · %d files", safeText(ref), len(p.Files)))
	review, dismiss := "[ r Review now ]", "[ x Dismiss ]"
	if m.screen == startScreen {
		for i, item := range m.pending {
			if item.ID == p.ID {
				if m.startFocus == 5+i*2 {
					review = ">" + review
				}
				if m.startFocus == 6+i*2 {
					dismiss = ">" + dismiss
				}
			}
		}
	}
	c.buttons(y+1, [2]string{review, "pending:review:" + p.ID}, [2]string{dismiss, "pending:dismiss:" + p.ID})
}
