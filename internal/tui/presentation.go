package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"devsecops-agent/internal/bridge"
	"devsecops-agent/internal/service"
	"github.com/charmbracelet/x/ansi"
)

type findingDetail struct{ text, raw string }
type pathCompletion struct{ value, hint string }

func display(value any) string {
	if value == nil {
		return "unknown"
	}
	return ansi.Strip(fmt.Sprint(value))
}
func recoveryAdvice(message string) string {
	text := strings.ToLower(message)
	switch {
	case strings.Contains(text, "report"), strings.Contains(text, "disk"), strings.Contains(text, "permission"), strings.Contains(text, "output"):
		return "Check artifact directory space and permissions, then export the retained run again."
	case strings.Contains(text, "unavailable"), strings.Contains(text, "scanner"), strings.Contains(text, "binary"):
		return "Check scanner availability and install the required tool before retrying."
	case strings.Contains(text, "checkout"), strings.Contains(text, "git"), strings.Contains(text, "dirty"):
		return "Choose a committed Java checkout; review Advanced options if local dirty content is intended."
	case strings.Contains(text, "timeout"), strings.Contains(text, "configuration"), strings.Contains(text, "threshold"), strings.Contains(text, "number"), strings.Contains(text, "timezone"):
		return "Correct the named Workspace option and review the settings again."
	default:
		return "Inspect this run's Activity and retained reports before retrying."
	}
}
func reviewSummary(checkout string, cfg service.Config, result map[string]any) string {
	manifest, _ := result["manifest"].(map[string]any)
	files, _ := manifest["inventory"].([]any)
	tools := "Semgrep + Gitleaks"
	if cfg.Profile == "full" {
		tools += " + isolated Maven, SpotBugs/FindSecBugs, Dependency-Check"
	}
	model := "Disabled (deterministic scan)"
	if cfg.Laya {
		model = "Advisory enabled; local model required"
	}
	dirty := "Clean checkout required"
	if cfg.AllowDirty {
		dirty = "Local dirty contents allowed; hashes recorded"
	}
	return fmt.Sprintf("Ready to scan\n\nCheckout: %s\nCommit: %s\nJava/JSP files: %d\nProfile: %s\nScanners: %s\nWall-clock limit: %d seconds\nMaximum files: %d\nThreshold: %s\nCheckout policy: %s\nLaya: %s\nArtifacts: %s\nDisplay timezone: %s\n\nCtrl+S starts this reviewed scan. V shows the full manifest.", checkout, display(manifest["commit"]), len(files), cfg.Profile, tools, cfg.Timeout, cfg.MaxFiles, cfg.FailOn, dirty, model, cfg.OutputDir, cfg.Timezone)
}
func describeFinding(data json.RawMessage) (findingDetail, error) {
	var item map[string]any
	if err := json.Unmarshal(data, &item); err != nil {
		return findingDetail{}, err
	}
	pretty, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return findingDetail{}, err
	}
	lines := []string{display(item["title"]), "", "Severity: " + display(item["severity"]) + " · " + display(item["cwe_category"]), "Verification / review: " + display(item["status"]), "Finding: " + display(item["finding_id"]), "", display(item["description"])}
	observations, _ := item["observations"].([]any)
	for _, raw := range observations {
		observation, _ := raw.(map[string]any)
		location, _ := observation["location"].(map[string]any)
		lines = append(lines, "", "Scanner: "+display(observation["tool"])+" · Rule: "+display(observation["rule_id"]), "Source: "+display(location["file_path"])+":"+display(location["line_start"]), display(observation["message"]))
		if snippet, ok := location["snippet"].(string); ok && snippet != "" {
			lines = append(lines, "Source excerpt (retained by the scanner):", ansi.Strip(snippet))
		} else {
			lines = append(lines, "No source excerpt was retained; use the source location above.")
		}
	}
	if references, ok := item["evidence_refs"].([]any); ok && len(references) > 0 {
		ids := []string{}
		for _, reference := range references {
			ids = append(ids, display(reference))
		}
		lines = append(lines, "", "Evidence records: "+strings.Join(ids, ", "))
	} else {
		lines = append(lines, "", "No evidence record references are attached.")
	}
	return findingDetail{strings.Join(lines, "\n"), string(pretty)}, nil
}
func eventText(event bridge.Event) string {
	stage := strings.ReplaceAll(event.Stage, "_", " ")
	return strings.TrimSpace(stage + " · " + event.Status + " · " + ansi.Strip(event.Message))
}
func resultText(result map[string]any) []string {
	if result == nil {
		return nil
	}
	lines := []string{fmt.Sprintf("Result: %s · gate %s · exit %s · %s findings", display(result["status"]), display(result["gate"]), display(result["exit_code"]), display(result["findings"]))}
	if errors, ok := result["errors"].([]any); ok {
		for _, value := range errors {
			message := display(value)
			lines = append(lines, "ERROR: "+message, "Next: "+recoveryAdvice(message))
		}
	} else if errors, ok := result["errors"].([]string); ok {
		for _, message := range errors {
			lines = append(lines, "ERROR: "+message, "Next: "+recoveryAdvice(message))
		}
	}
	if reports, ok := result["reports"].(map[string]any); ok {
		names := []string{}
		for name := range reports {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			lines = append(lines, "Report ("+name+"): "+display(reports[name]))
		}
	} else if reports, ok := result["reports"].(map[string]string); ok {
		names := []string{}
		for name := range reports {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			lines = append(lines, "Report ("+name+"): "+reports[name])
		}
	}
	if path, ok := result["summary_path"].(string); ok {
		lines = append(lines, "Summary: "+path)
	}
	return lines
}

// Directory reads run inside a tea.Cmd, never in the UI update or view.
func completePath(value string) pathCompletion {
	directory, prefix := filepath.Split(value)
	if directory == "" {
		directory = "."
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return pathCompletion{value, "Cannot complete this path: " + err.Error()}
	}
	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(strings.ToLower(entry.Name()), strings.ToLower(prefix)) {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 1 {
		return pathCompletion{filepath.Join(directory, names[0]) + string(filepath.Separator), "Directory completed. Enter finishes editing."}
	}
	if len(names) == 0 {
		return pathCompletion{value, "No matching directories."}
	}
	return pathCompletion{value, "Matching directories: " + strings.Join(names[:min(5, len(names))], ", ")}
}
