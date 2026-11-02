package chat

import "strings"

// Metadata and the complete diff share a bounded scroll surface. Every scroll
// path uses scroll(), including mouse, line, page and End. Wrapped physical
// lines count toward the end, so a long last line cannot unlock buttons early.
func (d *dialog) resize(width, bodyHeight int) {
	d.width = max(1, width)
	d.height = max(1, bodyHeight-5)
	d.input.SetWidth(max(1, width-4))
	payload := map[string]any{}
	for k, v := range d.payload {
		if k != "diff" {
			payload[k] = v
		}
	}
	parts := []string{d.detail, "AI recommendation: " + d.recommendation, "Payload:", textJSON(payload)}
	if diff, ok := d.payload["diff"].(string); ok {
		parts = append(parts, "Diff:", diff)
	}
	d.lines = wrap(strings.Join(parts, "\n"), d.width)
	d.scroll(0)
}
func (d *dialog) scroll(delta int) {
	d.offset = max(0, min(max(0, len(d.lines)-d.height), d.offset+delta))
	if d.offset+d.height >= len(d.lines) {
		d.diffSeenEnd = true
	}
}
