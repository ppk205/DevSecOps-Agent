package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/chat"
)

func TestMain(m *testing.M) {
	if os.Getenv("GO_CHAT_MAIN_HELPER") == "1" {
		if len(os.Args) != 3 || os.Args[1] != "-m" || os.Args[2] != "fake_chat_module" {
			os.Exit(4)
		}
		fmt.Println(`{"protocol":"devsec-chat/1","seq":1,"type":"models","items":[{"alias":"launch-fixture","models":["small"],"default_model":"small","local":true,"key_set":false}]}`)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestTuiStartsChatModel(t *testing.T) {
	t.Setenv("DEVSECOPS_PYTHON", os.Args[0])
	t.Setenv("DEVSECOPS_CHAT_MODULE", "fake_chat_module")
	t.Setenv("GO_CHAT_MAIN_HELPER", "1")
	m, err := newChatModel(nil, func(tea.Msg) {})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !strings.Contains(m.View().Content, "Start a harness session") {
		t.Fatal("tui did not start chat")
	}
	batch := m.Init()().(tea.BatchMsg)
	var state tea.Model = m
	// The first command is the receive arm; the helper emits models on startup.
	state, _ = state.Update(batch[0]())
	if !strings.Contains(state.(chat.Model).View().Content, "launch-fixture") {
		t.Fatal("chat module override not used")
	}
}

func TestPythonSrcDirAnchorsOnVenv(t *testing.T) {
	t.Setenv("DEVSECOPS_PYTHON", filepath.Join(t.TempDir(), ".venv", "Scripts", "python.exe"))
	if got := pythonSrcDir(); got != "" {
		t.Fatalf("pythonSrcDir() = %q, want empty (no src/ next to the venv)", got)
	}
	base := t.TempDir()
	src := filepath.Join(base, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEVSECOPS_PYTHON", filepath.Join(base, ".venv", "Scripts", "python.exe"))
	if got, want := pythonSrcDir(), src; got != want {
		t.Fatalf("pythonSrcDir() = %q, want %q", got, want)
	}
}

func TestPythonSrcDirIgnoresPATHFallback(t *testing.T) {
	t.Setenv("DEVSECOPS_PYTHON", "")
	if got := pythonSrcDir(); got != "" {
		t.Fatalf("pythonSrcDir() = %q, want empty for PATH fallback", got)
	}
}

func TestPythonEnvironmentFiltersAndReaddsPythonPath(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEVSECOPS_PYTHON", filepath.Join(base, ".venv", "Scripts", "python.exe"))
	t.Setenv("PYTHONPATH", "C:\\evil\\site-packages")
	t.Setenv("DEVSECOPS_PYTHON_ONLY", "1")
	t.Setenv("KEEP_ME", "still-here")

	env := pythonEnvironment()
	counts := map[string]int{}
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		counts[key]++
	}
	if counts["PYTHONPATH"] != 1 {
		t.Fatalf("PYTHONPATH appears %d times, want exactly 1: %v", counts["PYTHONPATH"], env)
	}
	if counts["DEVSECOPS_PYTHON_ONLY"] != 1 {
		t.Fatalf("DEVSECOPS_PYTHON_ONLY appears %d times, want exactly 1: %v", counts["DEVSECOPS_PYTHON_ONLY"], env)
	}
	if counts["KEEP_ME"] != 1 {
		t.Fatalf("unrelated env vars must pass through untouched, got: %v", env)
	}
	found := false
	for _, entry := range env {
		if strings.HasPrefix(entry, "PYTHONPATH=") && entry == "PYTHONPATH="+src {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected PYTHONPATH=%s in env: %v", src, env)
	}
}

func TestPythonEnvironmentPreservesUserPathWhenNoVenv(t *testing.T) {
	t.Setenv("DEVSECOPS_PYTHON", "")
	t.Setenv("PYTHONPATH", "C:\\user\\src")
	env := pythonEnvironment()
	got := ""
	for _, entry := range env {
		if strings.HasPrefix(entry, "PYTHONPATH=") {
			got = entry
		}
	}
	if got != "PYTHONPATH=C:\\user\\src" {
		t.Fatalf("user PYTHONPATH not preserved when no venv anchor: got %q in %v", got, env)
	}
}
