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

func (m Model) modelHint() string {
	if m.inputs[aiModeControl].Value() != "hunt" && m.inputs[aiReviewControl].Value() != "yes" && m.inputs[aiReportControl].Value() != "yes" {
		return "AI support: off. Choose Hunt or enable AI review/report in Advanced."
	}
	if m.modelStatus != "" {
		return m.modelStatus
	}
	selected := m.inputs[providerControl].Value()
	if selected == "" {
		if len(m.modelProfiles) == 0 {
			return "AI support: no provider profiles found. Add one with provider-add."
		}
		return "AI support: automatic keyed provider selection at review."
	}
	for _, profile := range m.modelProfiles {
		if profile.ID != selected {
			continue
		}
		key := "key missing"
		if profile.KeySet {
			key = "key set"
		}
		model := m.inputs[modelControl].Value()
		if model == "" {
			model = profile.DefaultModel
		}
		if model == "" {
			model = "model missing"
		}
		return "AI support: " + display(selected) + " / " + display(model) + " · " + key
	}
	return "AI support: selected profile is unavailable; check provider-add."
}
func recoveryAdvice(message string) string {
	text := strings.ToLower(message)
	switch {
	case strings.Contains(text, "report"), strings.Contains(text, "disk"), strings.Contains(text, "permission"), strings.Contains(text, "output"):
		return "Check artifact directory space and permissions, then export the retained run again."
	case strings.Contains(text, "unavailable"), strings.Contains(text, "scanner"), strings.Contains(text, "binary"):
		return "Check scanner availability and install the required tool before retrying."
	case strings.Contains(text, "checkout"), strings.Contains(text, "git"), strings.Contains(text, "dirty"):
		return "Choose a local source folder or repository URL. Git is needed for URLs and commit pins; review Advanced options for dirty Git checkouts."
	case strings.Contains(text, "timeout"), strings.Contains(text, "configuration"), strings.Contains(text, "threshold"), strings.Contains(text, "number"), strings.Contains(text, "timezone"):
		return "Correct the named Workspace option and review the settings again."
	default:
		return "Inspect this run's Activity and retained reports before retrying."
	}
}
func reviewSummary(checkout string, cfg service.Config, result map[string]any) string {
	manifest, _ := result["manifest"].(map[string]any)
	source := "Local Git checkout"
	if manifest["source_kind"] == "remote" {
		source = "Repository URL"
	} else if manifest["commit"] == "no-revision" {
		source = "Local source folder (no Git revision)"
	}
	if resolved, ok := manifest["resolved_checkout"].(string); ok && resolved != "" {
		checkout = resolved
	}
	identity := ""
	if repo, ok := manifest["repo_url"].(string); ok && repo != "" {
		identity = "\nRepository: " + display(repo)
	}
	if reason, ok := manifest["revision_reason"].(string); ok && reason != "" {
		identity += "\nRevision unavailable: " + display(reason)
	}
	files, _ := manifest["inventory"].([]any)
	tools := "Semgrep + native-hunt + Gitleaks"
	if cfg.Tools != nil {
		tools = strings.Join(cfg.Tools, ", ")
		if len(cfg.Tools) == 0 {
			tools = "No scanners selected"
		}
	} else if cfg.Profile == "full" {
		tools += " + isolated Maven, SpotBugs/FindSecBugs, Dependency-Check"
	}
	model := "Disabled"
	if cfg.Laya {
		model = "Advisory enabled; local model required"
	}
	ai := "Disabled"
	if cfg.AIEnabled() {
		provider, selectedModel := "automatic", "profile default"
		if cfg.ProviderProfile != nil {
			provider = *cfg.ProviderProfile
		}
		if cfg.ProviderModel != nil {
			selectedModel = *cfg.ProviderModel
		}
		ai = fmt.Sprintf("mode=%s · review=%t · report=%t\nProvider: %s\nModel: %s\nMaximum AI findings: %d", cfg.Mode, cfg.AIReview || cfg.Mode == "hunt", cfg.AIReport || cfg.Mode == "hunt", provider, selectedModel, cfg.MaxAIFindings)
	}
	if info, ok := result["ai_support"].(map[string]any); ok {
		ai += "\nAI provider status: " + display(info["status"]) + " · " + display(info["detail"])
	}
	dirty := "Clean checkout required"
	if cfg.AllowDirty {
		dirty = "Local dirty contents allowed; hashes recorded"
	}
	if manifest["commit"] == "no-revision" {
		dirty = "Unversioned; file hashes recorded"
	}
	return fmt.Sprintf("Ready to scan\n\nSource: %s%s\nCheckout: %s\nCommit: %s\nSource files: %d\nProfile: %s\nScanners: %s\nWall-clock limit: %d seconds\nMaximum files: %d\nThreshold: %s\nCheckout policy: %s\nLaya: %s\nAI support: %s\nArtifacts: %s\nDisplay timezone: %s\n\nCtrl+S starts this reviewed scan. V shows the full manifest.", source, identity, checkout, display(manifest["commit"]), len(files), cfg.Profile, tools, cfg.Timeout, cfg.MaxFiles, cfg.FailOn, dirty, model, ai, cfg.OutputDir, cfg.Timezone)
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
	metadata, _ := item["metadata"].(map[string]any)
	assessments, _ := metadata["ai_assessments"].([]any)
	if len(assessments) == 0 {
		lines = append(lines, "", "AI support: no assessment recorded; see Activity for stage status.")
	}
	for _, raw := range assessments {
		assessment, _ := raw.(map[string]any)
		lines = append(lines, "", "AI support explanation", "Provider: "+display(assessment["provider_id"])+" · Model: "+display(assessment["model_id"]), "Model proposal: "+display(assessment["proposed_status"]), "Explanation: "+display(assessment["rationale"]))
	}
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
	if usage := modelUsageText(result["ai_usage"]); usage != "" {
		lines = append(lines, usage)
	}
	if count := result["ai_assessment_count"]; count != nil {
		lines = append(lines, "AI assessments retained: "+display(count))
	} else if assessments, ok := result["assessments"].([]any); ok {
		lines = append(lines, fmt.Sprintf("AI assessments retained: %d", len(assessments)))
	}
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

func modelUsageText(value any) string {
	usage, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	tokens := "unavailable"
	if usage["total_tokens"] != nil {
		tokens = display(usage["total_tokens"]) + " reported"
	}
	return fmt.Sprintf("AI usage: %s finished calls · %s failed · tokens %s · cost unavailable", display(usage["requests"]), display(usage["failed_requests"]), tokens)
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
