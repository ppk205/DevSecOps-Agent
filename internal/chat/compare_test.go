package chat

import (
	"context"
	"strings"
	"testing"
)

type comparisonBaseline struct{ inertBaseline }

func (b comparisonBaseline) ComparisonFindings(context.Context) ([]map[string]string, error) {
	return []map[string]string{{"file": "BASELINE_ONLY_SECRET.java", "cwe": "CWE-89"}}, nil
}

func TestCompareCountsByFileAndCWE(t *testing.T) {
	c := Compare([]Finding{{"a/../A.java", "CWE-89"}, {"B.java", "CWE-79"}, {"C.java", "CWE-22"}}, []Finding{{"A.java", "CWE-89"}, {"B.java", "CWE-79"}, {"D.java", "CWE-89"}, {"E.java", "CWE-22"}, {"E.java", "CWE-22"}})
	if len(c.Both) != 2 || len(c.HarnessOnly) != 1 || len(c.BaselineOnly) != 2 {
		t.Fatal(c)
	}
}
func TestBaselineTabLabelledTestingOnly(t *testing.T) {
	m, _ := setup()
	m = click(m, "tab:1")
	view := m.View().Content
	for _, text := range []string{"Baseline comparison (testing only)", "Run baseline scan", "Compare with this session", "History"} {
		if !strings.Contains(view, text) {
			t.Fatal(view)
		}
	}
}
func TestBaselineResultsNeverSentToHost(t *testing.T) {
	m, h := setup()
	m.baseline = comparisonBaseline{}
	m = click(m, "tab:1")
	next, cmd := m.baselineAction("compare")
	m = next.(Model)
	if cmd == nil {
		t.Fatal("comparison not wired")
	}
	m = step(m, event("findings", map[string]any{"items": []map[string]any{{"file": "A.java", "cwe": "CWE-79", "status": "proposed"}}}))
	m = step(m, cmd())
	if m.comparison == nil || len(m.comparison.BaselineOnly) != 1 || len(m.comparison.HarnessOnly) != 1 {
		t.Fatal("comparison did not consume both sources")
	}
	if len(h.sent) != 1 || h.sent[0]["name"] != "findings" {
		t.Fatal(h.sent)
	}
	for _, sent := range h.sent {
		if strings.Contains(strings.ToLower(textJSON(sent)), "baseline_only_secret") {
			t.Fatal("baseline data leaked to host")
		}
	}
}
