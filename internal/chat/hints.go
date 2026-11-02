package chat

func (m Model) Hints() []string {
	switch {
	case m.disconnected:
		return []string{"r restart", "Ctrl+C twice quit", "? help"}
	case m.dialog != nil:
		if m.dialog.form != "" {
			return []string{"Enter submit", "Esc back", "? help"}
		}
		if m.dialog.gate == "G6" && !m.dialog.diffSeenEnd {
			return []string{"scroll to the end of the diff", "End last line", "Esc undecided", "? help"}
		}
		return []string{"←/→ select", "Enter answer", "PgUp/PgDn scroll", "Esc undecided", "? help"}
	case m.form != nil:
		return []string{"Tab next", "Enter save", "Esc cancel", "? help"}
	case m.confirmAuto:
		return []string{"y confirm auto", "n cancel", "? help"}
	case m.help:
		return []string{"Esc close help", "? help"}
	case m.tab == tabBaseline:
		return []string{"Ctrl+B compare", "Esc Chat", "? help"}
	case m.tab == tabKeys:
		return []string{"↑/↓ model", "←/→ action", "Enter activate", "a add model", "Esc Chat", "? help"}
	case m.screen == startScreen:
		return []string{"Tab next", "←/→ choose", "Enter activate", "? help"}
	case m.busy:
		return []string{"Esc stop", "? help"}
	case m.menuOpen():
		return []string{"↑/↓ choose", "Enter run", "Esc close", "? help"}
	default:
		return []string{"Enter send", "/ commands", "Esc stop", "? help"}
	}
}
