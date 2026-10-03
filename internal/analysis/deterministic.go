// Package analysis preserves the established finding and gate contracts.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Object map[string]any

var rank = map[string]int{"undetermined": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func text(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}
func object(value any) Object {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	if result, ok := value.(Object); ok {
		return result
	}
	return Object{}
}
func array(value any) []any {
	if result, ok := value.([]any); ok {
		return result
	}
	return nil
}

func Group(observations []Object, runID, stamp string) ([]Object, error) {
	groups := map[string][]Object{}
	keys := []string{}
	for _, observation := range observations {
		location := object(observation["location"])
		if text(location["file_path"]) == "" {
			continue
		}
		key := fmt.Sprintf("%s|%v|%s", text(location["file_path"]), location["line_start"], text(observation["cwe_category"]))
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], observation)
	}
	if stamp == "" {
		stamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	findings := []Object{}
	for _, key := range keys {
		observations := groups[key]
		first := observations[0]
		location := object(first["location"])
		hash := sha256.New()
		_, _ = hash.Write([]byte(key))
		rules := []string{}
		tools := map[string]bool{}
		refs := []string{}
		severity := "undetermined"
		for _, obs := range observations {
			rules = append(rules, text(obs["rule_id"]))
			tools[text(obs["tool"])] = true
			refs = append(refs, text(obs["observation_id"]))
			if rank[text(obs["severity"])] > rank[severity] {
				severity = text(obs["severity"])
			}
		}
		sort.Strings(rules)
		for _, rule := range rules {
			_, _ = hash.Write([]byte(rule))
		}
		fingerprint := hex.EncodeToString(hash.Sum(nil))
		id := fingerprint[:16]
		toolNames := []string{}
		for tool := range tools {
			toolNames = append(toolNames, tool)
		}
		sort.Strings(toolNames)
		cwe := text(first["cwe_category"])
		titleCWE := cwe
		if cwe == "" {
			cwe = "CWE-UNCLASSIFIED"
			titleCWE = "CWE-unknown"
		}
		where := fmt.Sprintf("%s:%v", location["file_path"], location["line_start"])
		title := titleCWE + " at " + where
		if symbol := text(location["symbol"]); symbol != "" {
			title = titleCWE + " in " + symbol + " (" + where + ")"
		}
		strength := "moderate"
		if len(tools) > 1 {
			strength = "strong"
		}
		group := Object{"group_id": id + "-g0", "finding_id": id, "tool_names": toolNames, "observation_ids": refs, "representative_observation_id": refs[0],
			"grouping_rationale": "same file, line, and CWE; merged conservatively — same-CWE findings at different sites stay distinct",
			"grouping_method":    "location-cwe", "grouped_at": stamp}
		findings = append(findings, Object{"finding_id": id, "run_id": runID, "fingerprint": fingerprint, "title": title, "description": first["message"],
			"cwe_category": cwe, "severity": severity, "status": "unprocessed", "observations": observations, "groups": []Object{group},
			"evidence_strength": strength, "evidence_refs": refs, "created_at": stamp, "updated_at": stamp,
			"metadata": Object{"grouping_key": []any{location["file_path"], location["line_start"], first["cwe_category"]}}})
		// Python's grouping key uses the empty string for missing CWEs.
		object(findings[len(findings)-1]["metadata"])["grouping_key"] = []any{location["file_path"], location["line_start"], text(first["cwe_category"])}
	}
	return findings, nil
}
func EffectiveSeverity(finding Object) (string, error) {
	metadata := object(finding["metadata"])
	validated := object(metadata["validated_assessment"])
	if text(validated["validated_by"]) == "independent-validator" {
		s := text(validated["severity"])
		if _, ok := rank[s]; !ok {
			return "", fmt.Errorf("invalid validated severity")
		}
		return s, nil
	}
	severity := text(finding["severity"])
	observations := array(finding["observations"])
	if len(observations) > 0 {
		severity = "undetermined"
		for _, raw := range observations {
			s := text(object(raw)["severity"])
			if _, ok := rank[s]; !ok {
				return "", fmt.Errorf("invalid observation severity")
			}
			if rank[s] > rank[severity] {
				severity = s
			}
		}
	}
	return severity, nil
}
func Gate(findings, results []Object, required []string, threshold string, coverageErrors, executionErrors []string, cancelled bool) (Object, error) {
	failures := append([]string{}, executionErrors...)
	failures = append(failures, coverageErrors...)
	byTool := map[string]Object{}
	for _, result := range results {
		byTool[text(result["tool"])] = result
	}
	for _, tool := range required {
		result := byTool[tool]
		if result == nil || text(result["status"]) != "completed" || len(array(result["errors"])) > 0 {
			failures = append(failures, tool+": required scanner did not complete successfully")
		}
	}
	exceeded, unknown := []string{}, []string{}
	for _, finding := range findings {
		decision := object(object(finding["metadata"])["validation_decision"])
		if text(finding["status"]) == "rejected" && text(decision["decided_by"]) == "independent-validator" && text(decision["new_status"]) == "rejected" {
			continue
		}
		severity, err := EffectiveSeverity(finding)
		if err != nil {
			return nil, err
		}
		id := text(finding["finding_id"])
		if severity == "undetermined" {
			unknown = append(unknown, id)
		}
		if threshold != "none" {
			target, ok := rank[threshold]
			if !ok {
				return nil, fmt.Errorf("invalid threshold")
			}
			if rank[severity] >= target {
				exceeded = append(exceeded, id)
			}
		}
	}
	code := 0
	if len(exceeded) > 0 {
		code = 1
	}
	if len(failures) > 0 {
		code = 2
	}
	if cancelled {
		code = 130
	}
	gate := "passed"
	if code != 0 {
		gate = "failed"
	}
	return Object{"exit_code": code, "gate": gate, "threshold": threshold, "exceeded": exceeded, "unknown_severity": unknown, "errors": failures}, nil
}
func DecodeObjects(raw json.RawMessage) ([]Object, error) {
	var objects []Object
	err := json.Unmarshal(raw, &objects)
	return objects, err
}
func CSVTools(finding Object) string {
	tools := map[string]bool{}
	for _, raw := range array(finding["observations"]) {
		tools[text(object(raw)["tool"])] = true
	}
	values := []string{}
	for tool := range tools {
		values = append(values, tool)
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}
