package analysis

import "testing"

func TestFR72GatePreservesUnprocessedAndValidatorAuthority(t *testing.T) {
	findings := []Object{{"finding_id": "f1", "severity": "high", "status": "rejected", "metadata": map[string]any{}, "observations": []any{}}}
	results := []Object{{"tool": "semgrep", "status": "completed", "errors": []any{}}}
	gate, err := Gate(findings, results, []string{"semgrep"}, "high", nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if gate["exit_code"] != 1 {
		t.Fatal("unverified rejection excluded a finding")
	}
	findings[0]["metadata"] = map[string]any{"validation_decision": map[string]any{"decided_by": "independent-validator", "new_status": "rejected"}}
	gate, err = Gate(findings, results, []string{"semgrep"}, "high", nil, nil, false)
	if err != nil || gate["exit_code"] != 0 {
		t.Fatal("independent rejection was not honored")
	}
	gate, err = Gate(findings, nil, []string{"semgrep"}, "high", nil, nil, false)
	if err != nil || gate["exit_code"] != 2 {
		t.Fatal("execution failure precedence changed")
	}
	gate, err = Gate(findings, nil, []string{"semgrep"}, "high", nil, nil, true)
	if err != nil || gate["exit_code"] != 130 {
		t.Fatal("cancellation precedence changed")
	}
}
func TestFR30GroupKeepsDifferentLocationsAndProvenance(t *testing.T) {
	observations := []Object{}
	for i, tool := range []string{"semgrep", "gitleaks"} {
		observations = append(observations, Object{"observation_id": tool, "tool": tool, "rule_id": "same-rule", "severity": "high", "message": "Evidence", "cwe_category": "CWE-89", "location": map[string]any{"file_path": "File.java", "line_start": 1 + i}})
	}
	grouped, err := Group(observations, "run-1", "2026-10-02T00:00:00+00:00")
	if err != nil {
		t.Fatal(err)
	}
	if len(grouped) != 2 || grouped[0]["finding_id"] == grouped[1]["finding_id"] {
		t.Fatal("grouping merged different sites")
	}
}
