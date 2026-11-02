package chat

import (
	"fmt"
	"strings"
)

type block struct {
	role, id, text, detail string
	expanded               bool
}

func (m *Model) appendBlock(role, text string) {
	m.blocks = append(m.blocks, block{role: role, text: text})
	m.follow()
}
func (m Model) transcriptText() string {
	parts := []string{}
	for _, b := range m.blocks {
		parts = append(parts, b.role+" › "+b.text)
		if b.expanded {
			parts = append(parts, b.detail)
		}
	}
	return strings.Join(parts, "\n")
}
func (m Model) transcriptLines() ([]string, []hit) {
	var lines []string
	var hits []hit
	for i, b := range m.blocks {
		prefix := b.role + " › "
		if b.role == "tool" {
			prefix = "▸ "
			if b.expanded {
				prefix = "▾ "
			}
			hits = append(hits, hit{x: 0, y: len(lines), width: m.width, action: fmt.Sprintf("block:%d", i)})
		}
		row := len(lines)
		lines = append(lines, wrap(prefix+b.text, m.width)...)
		if b.role == "remote" && strings.Contains(b.text, "copy link") {
			hits = append(hits, hit{x: 0, y: len(lines) - 1, width: m.width, action: "remote:copy"})
			_ = row
		}
		if b.expanded {
			lines = append(lines, wrap(b.detail, m.width)...)
		}
	}
	if len(lines) == 0 {
		lines = []string{"Ask about the target. AI hỗ trợ investigates gated candidates.", "Findings remain đề xuất (proposals) until a human decides."}
	}
	return lines, hits
}
func (m Model) transcriptHeight() int {
	h := m.bodyHeight() - 3
	if len(m.pending) > 0 {
		h -= 2
	}
	return max(1, h)
}
func (m *Model) scroll(delta int) {
	lines, _ := m.transcriptLines()
	m.offset = max(0, min(max(0, len(lines)-m.transcriptHeight()), m.offset+delta))
}
func (m *Model) follow() {
	lines, _ := m.transcriptLines()
	m.offset = max(0, len(lines)-m.transcriptHeight())
}
