package chat

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestStartLayoutGolden(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {75, 26}} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			m, _ := setup()
			m = step(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			lines := strings.Split(ansi.Strip(m.View().Content), "\n")
			for i := range lines {
				lines[i] = strings.TrimRight(lines[i], " ")
			}
			got := strings.Join(lines, "\n")
			want := "DevSecOps Agent · AI hỗ trợ · human decisions\n[ Chat ] Baseline Keys\nStart a harness session\n\n  Target: > Path to target\n\n  Model: No models added  [ ←/→ choose ]\n\n\n  Mode: ask  [ ←/→ choose ]\n\n> [ ＋ Add model ]\n\n  [ Start session ]\nEnter a target path." + strings.Repeat("\n", size[1]-16) + "No session · ask · 0 tokens · $0.0000\nTab next · ←/→ choose · Enter activate · ? help"
			if got != want {
				t.Fatalf("layout mismatch:\n%q", got)
			}
		})
	}
}
