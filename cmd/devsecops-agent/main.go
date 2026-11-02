package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/analysis"
	"devsecops-agent/internal/bridge"
	"devsecops-agent/internal/chat"
	"devsecops-agent/internal/dashboard"
	"devsecops-agent/internal/service"
	"devsecops-agent/internal/tui"
	"golang.org/x/term"
)

var version = "0.2.0"

func pythonExecutable() string {
	if value := os.Getenv("DEVSECOPS_PYTHON"); value != "" {
		return value
	}
	for _, path := range []string{filepath.Join(".venv", "Scripts", "python.exe"), filepath.Join(".venv", "bin", "python")} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			absolute, _ := filepath.Abs(path)
			return absolute
		}
	}
	return "python"
}
func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) > 0 && args[0] == "worker" {
		if err := analysis.Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 0
	}
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println(version)
		return 0
	}
	if len(args) == 0 {
		if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) {
			args = []string{"tui"}
		} else {
			help()
			return 0
		}
	}
	if args[0] == "--help" || args[0] == "-h" {
		return pythonCLI(args)
	}
	command := args[0]
	if !map[string]bool{"tui": true, "serve": true, "scan-list": true, "scan-status": true, "scan-run": true, "scan-retry": true, "scan-cancel": true, "scan-export": true}[command] {
		return pythonCLI(args)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	db := flags.String("db-path", "vulnscan.db", "SQLite database")
	checkout := flags.String("checkout", ".", "Local Git checkout")
	profile := flags.String("profile", "", "fast or full")
	configPath := flags.String("config", "", "Versioned configuration JSON")
	threshold := flags.String("fail-on", "", "Severity threshold")
	out := flags.String("out", "", "Artifact output directory")
	repo := flags.String("repo", "local", "Repository identity")
	commit := flags.String("commit", "", "Expected commit")
	publicID := flags.String("run-id", "", "Public run ID")
	timeout := flags.Int("timeout", 0, "Scan wall-clock seconds")
	jsonOutput := flags.Bool("json", false, "JSON output")
	ci := flags.Bool("ci", false, "CI containment and cleanliness policy")
	dirty := flags.Bool("allow-dirty", false, "Consent to local dirty content")
	laya := flags.Bool("laya", false, "Enable advisory Laya routing")
	layaConfig := flags.String("laya-config", "", "Laya configuration")
	format := flags.String("fmt", "json", "Report format")
	host := flags.String("host", "127.0.0.1", "Local dashboard host")
	port := flags.Int("port", 8000, "Dashboard port")
	// Permit legacy positional run IDs before flags.
	position := ""
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		position = rest[0]
		rest = rest[1:]
	}
	if err := flags.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if position == "" && len(flags.Args()) > 0 {
		position = flags.Args()[0]
	}
	if command == "serve" && !dashboard.LocalHost(*host) {
		fmt.Fprintln(os.Stderr, "The dashboard must bind to localhost")
		return 2
	}
	client, err := bridge.Start(pythonExecutable(), *db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	backend := &service.Backend{Client: client, DBPath: *db}
	defer backend.Close()
	if command == "tui" {
		var program *tea.Program
		model, chatErr := newChatModel(backend, func(msg tea.Msg) { program.Send(msg) })
		if chatErr != nil {
			fmt.Fprintln(os.Stderr, chatErr)
			return 2
		}
		defer model.Close()
		program = tea.NewProgram(model)
		var final tea.Model
		final, err = program.Run()
		if current, ok := final.(chat.Model); ok {
			current.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = backend.Init(initCtx)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if command == "serve" {
		server := dashboard.Server{Backend: backend, Output: defaultString(*out, "artifacts/reports")}
		if err = server.Serve(ctx, *host, *port); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 0
	}
	if command == "scan-list" {
		rows, e := backend.Store.AllHistory(ctx)
		if e != nil || *jsonOutput {
			return output(rows, e)
		}
		for _, row := range rows {
			fmt.Printf("%d\tattempt=%d\t%s\n", row.ID, row.Attempt, row.Status)
		}
		return 0
	}
	if command == "scan-status" {
		if position == "" {
			fmt.Fprintln(os.Stderr, "run ID is required")
			return 2
		}
		info, e := backend.Store.Summary(ctx, position)
		if e != nil {
			fmt.Fprintln(os.Stderr, "run not found")
			return 1
		}
		if *jsonOutput {
			return output(info, nil)
		}
		fmt.Printf("id=%d run=%s status=%s\n", info.ID, info.RunID, info.Status)
		return 0
	}
	if command == "scan-cancel" {
		e := backend.Cancel(ctx, position)
		if e != nil || *jsonOutput {
			return output(map[string]bool{"cancel_requested": true}, e)
		}
		return 0
	}
	if command == "scan-export" {
		path, e := backend.Export(ctx, position, *format, defaultString(*out, "artifacts"))
		if e != nil {
			return output(nil, e)
		}
		fmt.Println(path)
		return 0
	}
	progress := func(event bridge.Event) {
		if !*jsonOutput {
			fmt.Fprintf(os.Stderr, "%s: %s %s\n", event.Stage, event.Status, event.Message)
		}
	}
	var result map[string]any
	if command == "scan-retry" {
		result, err = backend.Retry(ctx, position, progress)
	} else {
		values := map[string]any{}
		flags.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "fail-on":
				values["fail_on"] = *threshold
			case "out":
				values["output_dir"] = *out
			case "timeout":
				values["timeout"] = *timeout
			case "ci":
				values["ci"] = *ci
			case "allow-dirty":
				values["allow_dirty"] = *dirty
			case "laya":
				values["laya"] = *laya
			case "laya-config":
				values["laya_config_path"] = *layaConfig
			}
		})
		cfg, e := service.Resolve(*profile, *configPath, values)
		if e != nil {
			return failureSummary(*out, e)
		}
		if !*jsonOutput {
			data, _ := json.MarshalIndent(cfg, "", "  ")
			fmt.Println(string(data))
		}
		params := map[string]any{"checkout": *checkout, "configuration": cfg, "repo": *repo, "commit": *commit}
		if *publicID != "" {
			params["public_id"] = *publicID
		}
		result, err = backend.Run(ctx, params, progress)
	}
	if errors.Is(err, context.Canceled) {
		result = map[string]any{"status": "cancelled", "gate": "failed", "exit_code": 130}
		err = nil
	}
	if err != nil {
		return failureSummary(*out, err)
	}
	_ = output(result, nil)
	if code, ok := result["exit_code"].(float64); ok {
		return int(code)
	}
	if code, ok := result["exit_code"].(int); ok {
		return code
	}
	return 2
}

func newChatModel(backend tui.API, send func(tea.Msg)) (chat.Model, error) {
	host, err := bridge.StartChat(pythonExecutable(), pythonEnvironment())
	if err != nil {
		return chat.Model{}, err
	}
	baseline := tui.NewEmbedded(backend)
	baseline.Send = send
	model := chat.New(host, baseline)
	model.Restart = func() (chat.Host, error) { return bridge.StartChat(pythonExecutable(), pythonEnvironment()) }
	return model, nil
}
func failureSummary(directory string, err error) int {
	result := map[string]any{"status": "failed", "gate": "failed", "exit_code": 2, "errors": []string{err.Error()}, "run_id": nil}
	directory = defaultString(directory, "artifacts")
	if e := os.MkdirAll(directory, 0700); e == nil {
		data, _ := json.MarshalIndent(result, "", "  ")
		_ = os.WriteFile(filepath.Join(directory, "summary.json"), data, 0600)
	}
	_ = output(result, nil)
	return 2
}
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func output(value any, err error) int {
	if err != nil {
		value = map[string]any{"status": "failed", "gate": "failed", "exit_code": 2, "errors": []string{err.Error()}}
	}
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	fmt.Println(string(data))
	if err != nil {
		return 2
	}
	return 0
}

// pythonEnvironment builds the child env for the Python side. A PYTHONPATH
// inherited from the caller can point at some other environment's
// site-packages and shadow this install's compiled wheels (a pydantic_core
// built for a different interpreter ABI loads and then fails at import), so
// the key is filtered and re-added pointing at the repo's own src when one
// exists next to the selected interpreter's venv; otherwise the user's
// PYTHONPATH is preserved.
func pythonEnvironment() []string {
	env := make([]string, 0, len(os.Environ())+2)
	var userPythonPath string
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case "PYTHONPATH":
			userPythonPath = value
		case "DEVSECOPS_PYTHON_ONLY":
			// re-added below
		default:
			env = append(env, entry)
		}
	}
	env = append(env, "DEVSECOPS_PYTHON_ONLY=1")
	if src := pythonSrcDir(); src != "" {
		env = append(env, "PYTHONPATH="+src)
	} else if userPythonPath != "" {
		env = append(env, "PYTHONPATH="+userPythonPath)
	}
	return env
}

// pythonSrcDir locates <repo>/src relative to the selected interpreter's venv
// (<venv>/Scripts/python.exe on Windows, <venv>/bin/python elsewhere) so the
// launcher works from any working directory.
func pythonSrcDir() string {
	exe := pythonExecutable()
	if exe == "" || exe == "python" || exe == "python3" {
		return "" // PATH fallback; no venv to anchor on
	}
	venv := filepath.Dir(filepath.Dir(exe))
	base := filepath.Base(venv)
	if base != ".venv" && base != "venv" {
		return "" // not inside a venv; keep the user's PYTHONPATH
	}
	src := filepath.Join(filepath.Dir(venv), "src")
	if info, err := os.Stat(src); err == nil && info.IsDir() {
		return src
	}
	return ""
}

func pythonCLI(args []string) int {
	cmd := exec.Command(pythonExecutable(), append([]string{"-m", "vulnscan.cli.main"}, args...)...)
	cmd.Env = pythonEnvironment()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}
func help() {
	fmt.Println("DevSecOps Agent — native terminal interface\n\nCommands: tui, scan-run, scan-list, scan-status, scan-cancel, scan-retry, scan-export\nExisting target, dashboard, evaluation and provider commands are supported through Python.\n\n--version  Installed release version\n--help     Show help\n\nSet DEVSECOPS_PYTHON to select the Python environment.")
}
