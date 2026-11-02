package chat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/bridge"
)

// Exercise the real stdio adapter with a recorded transport. Its working
// directory contains only test fixtures, so no project credentials are loaded.
func TestPythonHostRoundTripFromStartFormAndRestart(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	python := ""
	for _, candidate := range []string{filepath.Join(root, ".venv", "Scripts", "python.exe"), filepath.Join(root, ".venv", "bin", "python")} {
		if _, err := os.Stat(candidate); err == nil {
			python = candidate
			break
		}
	}
	if python == "" {
		t.Skip("Python project environment unavailable; helper-process bridge tests still run")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	fixture := `[{"message":{"role":"assistant","tool_calls":[{"id":"plan-1","name":"propose_scan_plan","arguments":{"scope":["*.java"],"classes":["CWE-89"]}}]},"usage":{"input_tokens":2,"output_tokens":3},"model":"fixture"},{"message":{"role":"assistant","content":"Recorded review complete."},"usage":{"input_tokens":1,"output_tokens":1},"model":"fixture"}]`
	script := filepath.Join(dir, "replies.json")
	if err := os.WriteFile(script, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYTHONPATH", filepath.Join(root, "src"))
	t.Setenv("DEVSEC_CHAT_FAKE_TRANSPORT", script)
	t.Setenv("DEVSECOPS_CHAT_MODULE", "vulnscan.harness.rpc")
	t.Chdir(dir)
	h, err := bridge.StartChat(python, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	m := New(h, nil)
	next := func(kind string) {
		t.Helper()
		deadline := time.NewTimer(15 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case e, ok := <-m.host.Events():
				if !ok {
					t.Fatalf("host disconnected: %v", m.host.Err())
				}
				m = step(m, e)
				if e.Type == "error" {
					var data map[string]any
					_ = json.Unmarshal(e.Raw, &data)
					t.Fatalf("host error: %v", data["message"])
				}
				if e.Type == kind {
					return
				}
			case <-deadline.C:
				t.Fatalf("timed out waiting for %s", kind)
			}
		}
	}
	m = click(m, "model:add")
	for i, value := range []string{"fixture-local", "Custom", "openai_compatible", "http://127.0.0.1:1/v1", "fixture", ""} {
		m.form.fields[i].SetValue(value)
	}
	m = click(m, "form:submit")
	next("models")
	m.target.SetValue(target)
	m = click(m, "start")
	next("permission_request")
	if m.dialog.gate != "G0" {
		t.Fatal("start did not ask G0")
	}
	m = press(m, tea.KeyEnter)
	if m.dialog == nil {
		t.Fatal("bare Enter answered G0")
	}
	m = press(m, tea.KeyRight)
	m = press(m, tea.KeyEnter)
	next("done")
	m.input.SetValue("Review the fixture")
	m = press(m, tea.KeyEnter)
	next("permission_request")
	if m.dialog.gate != "G1" {
		t.Fatal("plan gate missing")
	}
	m = press(m, 'y')
	next("done")
	if !strings.Contains(m.transcriptText(), "Recorded review complete.") || m.tokens != 7 {
		t.Fatalf("reply or usage missing: %s / %d", m.transcriptText(), m.tokens)
	}
	if m.sessionPath == "" {
		t.Fatal("ready did not expose session log for restart")
	}
	m.Restart = func() (Host, error) { return bridge.StartChat(python, os.Environ()) }
	h.Close()
	m = step(m, disconnectedMsg{})
	u, cmd := m.Update(tea.KeyPressMsg{Code: 'r'})
	m = u.(Model)
	m = step(m, cmd())
	defer m.Close()
	next("permission_request")
	if m.dialog.gate != "G0" {
		t.Fatal("restart must re-request G0")
	}
	m = press(m, 'y')
	next("done")
	if m.disconnected || m.screen != chatScreen {
		t.Fatal("restart did not return to chat")
	}
}
