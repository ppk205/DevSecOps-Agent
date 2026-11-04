package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"devsecops-agent/internal/analysis"
	"devsecops-agent/internal/bridge"
)

func objects(value any) []analysis.Object {
	data, _ := json.Marshal(value)
	var result []analysis.Object
	_ = json.Unmarshal(data, &result)
	return result
}
func obj(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	if result, ok := value.(analysis.Object); ok {
		return result
	}
	return map[string]any{}
}
func stringsList(value any) []string {
	data, _ := json.Marshal(value)
	var result []string
	_ = json.Unmarshal(data, &result)
	return result
}
func (b *Backend) helper(ctx context.Context, method string, params any, target any) error {
	return b.Client.Call(ctx, method, params, target, nil)
}
func (b *Backend) review(ctx context.Context, checkout, commit string, cfg Config, workdir string) (map[string]any, error) {
	var result map[string]any
	err := b.helper(ctx, "review", map[string]any{"checkout": checkout, "commit": commit, "workdir": workdir, "configuration": cfg}, &result)
	return obj(result["manifest"]), err
}
func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func snapshot(checkout, root string, files map[string]any, ctx context.Context) error {
	for name, expected := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel := filepath.FromSlash(name)
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("source path escapes snapshot")
		}
		source := filepath.Join(checkout, rel)
		info, err := os.Lstat(source)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("snapshot source is not a regular file")
		}
		destination := filepath.Join(root, rel)
		if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		input.Close()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		actual, err := hashFile(destination)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("checkout changed while preparing immutable snapshot")
		}
	}
	return nil
}

func (b *Backend) nativeRun(ctx context.Context, params map[string]any, eventCallback func(bridge.Event)) (map[string]any, error) {
	if !b.runMu.TryLock() {
		return nil, fmt.Errorf("another scan is active in this database")
	}
	defer b.runMu.Unlock()
	var acquired map[string]any
	leaseCtx, leaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
	leaseErr := b.helper(leaseCtx, "lease_acquire", map[string]any{}, &acquired)
	leaseCancel()
	if leaseErr != nil {
		return nil, leaseErr
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b.helper(release, "lease_release", map[string]any{}, nil)
	}()
	var cfg Config
	data, _ := json.Marshal(params["configuration"])
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	checkout := fmt.Sprint(params["checkout"])
	var err error
	publicID, _ := params["public_id"].(string)
	if publicID == "" {
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return nil, err
		}
		publicID = "run-" + hex.EncodeToString(id[:])
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`).MatchString(publicID) {
		return nil, fmt.Errorf("invalid public run ID")
	}
	if _, err = b.Store.Summary(ctx, publicID); err == nil {
		return nil, fmt.Errorf("run ID already exists; choose a new attempt ID")
	}
	output, err := filepath.Abs(filepath.Join(cfg.OutputDir, publicID))
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		return nil, fmt.Errorf("run artifact directory already exists; choose a new run ID")
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		return nil, err
	}
	commit, _ := params["commit"].(string)
	workdir, _ := params["workdir"].(string)
	if workdir == "" {
		workdir = "harness"
	}
	repo, _ := params["repo"].(string)
	if repo == "" {
		repo = "local"
	}
	var spec map[string]any
	if err = b.helper(ctx, "specification", map[string]any{"configuration": cfg, "checkout": checkout, "commit": commit, "repo": repo, "public_id": publicID}, &spec); err != nil {
		return nil, err
	}
	parentID, _ := params["parent_id"].(int)
	pk, _, err := b.Store.AddRun(context.Background(), publicID, spec, parentID)
	if err != nil {
		return nil, err
	}
	scanCtx, stop := context.WithCancel(ctx)
	defer stop()
	deadlineCtx, deadlineStop := context.WithTimeout(scanCtx, time.Duration(cfg.Timeout)*time.Second)
	defer deadlineStop()
	go func() {
		timer := time.NewTicker(100 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-scanCtx.Done():
				return
			case <-timer.C:
				flag, e := b.Store.CancelRequested(scanCtx, pk)
				if e == nil && flag {
					stop()
					return
				}
			}
		}
	}()
	started := time.Now()
	events := []bridge.Event{}
	results := []analysis.Object{}
	findings := []analysis.Object{}
	executionErrors := []string{}
	routing := []any{}
	manifest := map[string]any{"inventory": []string{}, "files": map[string]any{}}
	coverage := func() map[string]any {
		value := map[string]any{}
		for _, result := range results {
			value[fmt.Sprint(result["tool"])] = result["coverage_records"]
		}
		return value
	}
	persist := func(stage, status, message string) error {
		var clean string
		if e := b.helper(context.Background(), "sanitize", map[string]any{"value": message}, &clean); e != nil {
			clean = "Stage failed; worker unavailable"
		}
		event := bridge.Event{RunID: publicID, PK: pk, Stage: stage, Status: status, Timestamp: utcStamp(), Message: clean, Sequence: len(events) + 1}
		events = append(events, event)
		err := b.Store.Persist(context.Background(), pk, spec, map[string]any{"scanner_results": results, "coverage": coverage()}, events, findings)
		if err == nil && eventCallback != nil {
			eventCallback(event)
		}
		return err
	}
	runErr := func() error {
		if e := persist("intake", "running", ""); e != nil {
			return e
		}
		var e error
		manifest, e = b.review(deadlineCtx, checkout, commit, cfg, workdir)
		if e != nil {
			return e
		}
		resolved, ok := manifest["resolved_checkout"].(string)
		if !ok || resolved == "" {
			return fmt.Errorf("source review did not return a local checkout path")
		}
		checkout = resolved
		commit, _ = manifest["commit"].(string)
		spec["repository_checkout_path"] = checkout
		if repo == "local" && manifest["source_kind"] == "remote" {
			spec["target_repository_url"] = manifest["repo_url"]
		}
		spec["target_commit_sha"] = manifest["commit"]
		metadata := obj(spec["metadata"])
		metadata["manifest"] = manifest
		spec["metadata"] = metadata
		root, e := os.MkdirTemp("", "vulnscan-snapshot-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(root)
		if e = snapshot(checkout, root, obj(manifest["files"]), deadlineCtx); e != nil {
			return e
		}
		execution := map[string]any{}
		for key, value := range spec {
			execution[key] = value
		}
		execution["repository_checkout_path"] = root
		intakeMessage := "Verified commit " + commit
		if commit == "no-revision" {
			intakeMessage = "Source snapshot hashed; no committed Git revision is available"
		}
		if e = persist("intake", "completed", intakeMessage); e != nil {
			return e
		}
		for _, toolConfig := range objects(spec["tools"]) {
			if e = deadlineCtx.Err(); e != nil {
				return e
			}
			tool := fmt.Sprint(toolConfig["tool"])
			if e = persist(tool, "running", ""); e != nil {
				return e
			}
			var result analysis.Object
			remaining := time.Duration(cfg.Timeout)*time.Second - time.Since(started)
			e = b.helper(deadlineCtx, "scan_tool", map[string]any{"tool": tool, "profile": cfg.Profile, "timeout": remaining.Seconds(), "specification": execution}, &result)
			if deadlineCtx.Err() != nil {
				return deadlineCtx.Err()
			}
			if e != nil {
				executionErrors = append(executionErrors, tool+": "+e.Error())
				if e = persist(tool, "failed", executionErrors[len(executionErrors)-1]); e != nil {
					return e
				}
				continue
			}
			if fmt.Sprint(result["run_id"]) != publicID || fmt.Sprint(result["tool"]) != tool {
				return fmt.Errorf("scanner result identity does not match scan specification")
			}
			observations := objects(result["observations"])
			for _, observation := range observations {
				location := obj(observation["location"])
				name := fmt.Sprint(location["file_path"])
				source := filepath.Join(root, filepath.FromSlash(name))
				if filepath.IsAbs(name) {
					source = name
				}
				rel, e := filepath.Rel(root, source)
				if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return fmt.Errorf("scanner evidence path escapes source snapshot")
				}
				location["file_path"] = filepath.ToSlash(rel)
				if bytes, e := os.ReadFile(source); e == nil {
					if tool == "gitleaks" {
						location["snippet"] = "[REDACTED: secret evidence]"
					} else {
						line := intNumber(location["line_start"])
						lines := strings.Split(strings.ReplaceAll(strings.ReplaceAll(strings.ToValidUTF8(string(bytes), "�"), "\r\n", "\n"), "\r", "\n"), "\n")
						if len(lines) > 0 && lines[len(lines)-1] == "" {
							lines = lines[:len(lines)-1]
						}
						start, end := max(0, line-1), min(len(lines), line+2)
						snippet := ""
						if start < end {
							snippet = strings.Join(lines[start:end], "\n")
						}
						runes := []rune(snippet)
						if len(runes) > 2000 {
							runes = runes[:2000]
						}
						location["snippet"] = string(runes)
					}
				}
				observation["location"] = location
				observation["rule_pack_version"] = spec["rules_packs_version"]
			}
			result["observations"] = observations
			recount(result)
			artifact := filepath.Join(output, "scanner-"+tool+".json")
			for _, observation := range observations {
				observation["raw_output_ref"] = artifact
			}
			var sanitized analysis.Object
			if e = b.helper(deadlineCtx, "sanitize", map[string]any{"value": result}, &sanitized); e != nil {
				return e
			}
			result = sanitized
			bytes, _ := json.MarshalIndent(result, "", "  ")
			if e = os.WriteFile(artifact, bytes, 0600); e != nil {
				return e
			}
			hash := sha256.Sum256(bytes)
			refs := objects(result["raw_output_refs"])
			refs = append(refs, analysis.Object{"version": "0.1.0", "path": artifact, "checksum_sha256": hex.EncodeToString(hash[:]), "mime_type": "application/json", "size_bytes": len(bytes)})
			result["raw_output_refs"] = refs
			results = append(results, result)
			all := []analysis.Object{}
			for _, result := range results {
				all = append(all, objects(result["observations"])...)
			}
			grouped, e := analysis.Group(all, publicID, utcStamp())
			if e != nil {
				return e
			}
			if e = b.helper(deadlineCtx, "validate_findings", map[string]any{"findings": grouped}, &findings); e != nil {
				return e
			}
			if e = persist(tool, fmt.Sprint(result["status"]), strings.Join(stringsList(result["errors"]), "; ")); e != nil {
				return e
			}
		}
		after, e := b.review(deadlineCtx, checkout, commit, cfg, workdir)
		if e != nil {
			return e
		}
		if marshal(after["files"]) != marshal(manifest["files"]) || after["commit"] != manifest["commit"] {
			executionErrors = append(executionErrors, "checkout contents changed during scanning; retry from a stable checkout")
		}
		var advisory map[string]any
		if cfg.Laya && !cfg.CI && len(findings) > 0 {
			if e = persist("laya_batch_routing", "running", "Loading or running the advisory model"); e != nil {
				return e
			}
		}
		if e = b.helper(deadlineCtx, "routing", map[string]any{"configuration": cfg, "specification": spec, "findings": findings}, &advisory); e != nil {
			return e
		}
		routing, _ = advisory["routing"].([]any)
		if routing == nil {
			routing = []any{}
		}
		metadata["advisory_configuration"] = advisory["advisory_configuration"]
		stage := obj(advisory["stage"])
		if e = persist(fmt.Sprint(stage["name"]), fmt.Sprint(stage["status"]), fmt.Sprint(stage["detail"])); e != nil {
			return e
		}
		if e = persist("targeted_deep_analysis", "skipped", "AI support is disabled; choose Hunt or enable AI review to run the model"); e != nil {
			return e
		}
		return persist("independent_validation", "skipped", "No assessment evidence supplied; findings remain unprocessed")
	}()
	wasCancelled := errors.Is(runErr, context.Canceled) && ctx.Err() != context.DeadlineExceeded
	if runErr != nil {
		if wasCancelled {
			_ = persist("execution", "cancelled", "Scan cancelled; partial evidence retained")
		} else {
			executionErrors = append(executionErrors, runErr.Error())
			_ = persist("execution", "failed", runErr.Error())
		}
	}
	required := []string{}
	for _, tool := range objects(spec["tools"]) {
		required = append(required, fmt.Sprint(tool["tool"]))
	}
	policy, e := analysis.Gate(findings, results, required, cfg.FailOn, reconcile(results, manifest), executionErrors, wasCancelled)
	if e != nil {
		return nil, e
	}
	status := "completed"
	if wasCancelled {
		status = "cancelled"
	} else if policy["exit_code"] == 2 {
		status = "failed"
	}
	summary := map[string]any{"schema_version": 1, "application_version": b.Version, "id": pk, "run_id": publicID, "commit": spec["target_commit_sha"], "manifest": manifest, "configuration": cfg, "status": status, "findings": len(findings), "scanner_results": results, "coverage": coverage(), "stages": events, "routing": routing, "reports": map[string]any{}}
	for key, value := range policy {
		summary[key] = value
	}
	var cleanSummary map[string]any
	if e = b.helper(context.Background(), "sanitize", map[string]any{"value": summary}, &cleanSummary); e == nil {
		summary = cleanSummary
	}
	if e = b.Store.Finish(context.Background(), pk, summary); e != nil {
		return nil, e
	}
	var exported struct {
		Reports map[string]string `json:"reports"`
		Errors  []string          `json:"errors"`
	}
	if e = b.helper(context.Background(), "reports", map[string]any{"summary": summary, "findings": findings, "output": output}, &exported); e != nil {
		summary["errors"] = append(stringsList(summary["errors"]), "report export failed: "+e.Error())
		if !wasCancelled {
			summary["status"] = "failed"
			summary["exit_code"] = 2
			summary["gate"] = "failed"
		}
	} else {
		summary["reports"] = exported.Reports
		if len(exported.Errors) > 0 {
			summary["errors"] = append(stringsList(summary["errors"]), exported.Errors...)
			if !wasCancelled {
				summary["status"] = "failed"
				summary["exit_code"] = 2
				summary["gate"] = "failed"
			}
		}
	}
	summary["summary_path"] = filepath.Join(output, "summary.json")
	if e = os.WriteFile(fmt.Sprint(summary["summary_path"]), []byte(marshal(summary)), 0600); e != nil {
		return nil, e
	}
	if e = b.Store.Finish(context.Background(), pk, summary); e != nil {
		return nil, e
	}
	// Completion may follow cancellation: retain evidence first, then notify.
	notificationCtx, notificationCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer notificationCancel()
	receipt, notificationError := b.Notification(notificationCtx, map[string]any{"action": "complete", "run_id": pk})
	if notificationError != nil {
		summary["notifications"] = map[string]any{"status": "unknown", "detail": "Notification completion was not acknowledged; check retained receipts"}
	} else {
		summary["notifications"] = receipt
	}
	return summary, nil
}
func intNumber(value any) int {
	if number, ok := value.(float64); ok {
		return int(number)
	}
	if number, ok := value.(int); ok {
		return number
	}
	return 0
}
func recount(result analysis.Object) {
	units := map[string]analysis.Object{}
	for _, record := range objects(result["coverage_records"]) {
		if record["eligible"] == true {
			units[fmt.Sprint(record["unit_language"])+"|"+fmt.Sprint(record["unit_path"])] = record
		}
	}
	analyzed, failed, skipped := 0, 0, 0
	for _, record := range units {
		switch record["status"] {
		case "analyzed":
			analyzed++
		case "failed", "not_processed":
			failed++
		case "skipped", "unsupported":
			skipped++
		}
	}
	percent := 0.0
	if len(units) > 0 {
		percent = 100 * float64(analyzed) / float64(len(units))
	}
	result["eligible_units"] = len(units)
	result["analyzed_units"] = analyzed
	result["failed_units"] = failed
	result["skipped_units"] = skipped
	result["coverage_percent"] = percent
}
func reconcile(results []analysis.Object, manifest map[string]any) []string {
	errors := []string{}
	inventory := stringsList(manifest["inventory"])
	for _, result := range results {
		tool := fmt.Sprint(result["tool"])
		observations := objects(result["observations"])
		if len(observations) > 0 && observations[0]["run_id"] != result["run_id"] {
			errors = append(errors, tool+": observation run identity mismatch")
		}
		units := map[string]analysis.Object{}
		for _, record := range objects(result["coverage_records"]) {
			name := strings.ReplaceAll(fmt.Sprint(record["unit_path"]), "\\", "/")
			units[name] = record
			status := fmt.Sprint(record["status"])
			if record["eligible"] == true && status != "analyzed" && status != "unsupported" && status != "not_eligible" {
				errors = append(errors, fmt.Sprintf("%s: incomplete coverage: %s: %s", tool, name, status))
			}
		}
		if result["status"] != "completed" || len(stringsList(result["errors"])) > 0 {
			continue
		}
		expected := inventory
		if tool == "owasp-dependency-check" {
			expected = []string{"pom.xml"}
		}
		for _, name := range expected {
			record := units[name]
			status := fmt.Sprint(record["status"])
			if record == nil {
				errors = append(errors, tool+": missing coverage for "+name)
			} else if status != "analyzed" && status != "unsupported" && status != "not_eligible" {
				errors = append(errors, fmt.Sprintf("%s: %s: %s", tool, name, status))
			} else if status == "unsupported" && (record["limitation_reason"] == nil || record["limitation_reason"] == "") {
				errors = append(errors, tool+": unsupported coverage needs a reason: "+name)
			}
		}
	}
	return errors
}
