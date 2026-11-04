package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestQR20PythonExecutableFindsEnvironmentBesideBinary(t *testing.T) {
	for _, tc := range []struct {
		platform string
		venv     string
		python   string
	}{
		{"windows", ".venv", filepath.Join("Scripts", "python.exe")},
		{"linux", ".venv", filepath.Join("bin", "python")},
		{"darwin", ".venv", filepath.Join("bin", "python")},
		{"linux", ".venv-linux", filepath.Join("bin", "python")},
		{"windows", "venv", filepath.Join("Scripts", "python.exe")},
		{"darwin", "venv", filepath.Join("bin", "python")},
	} {
		t.Run(tc.platform+"/"+tc.venv, func(t *testing.T) {
			t.Setenv("DEVSECOPS_PYTHON", "")
			t.Setenv("VIRTUAL_ENV", "")
			root := filepath.Join(t.TempDir(), "application with spaces")
			want := filepath.Join(root, tc.venv, tc.python)
			writePythonFixture(t, want)
			// The caller may be inside bin or anywhere else on the machine.
			for _, cwd := range []string{root, filepath.Join(root, "bin"), t.TempDir()} {
				got := pythonExecutableAt(filepath.Join(root, "bin", "devsecops-agent-go"), cwd, tc.platform)
				if got != want {
					t.Fatalf("from %q: python = %q, want %q", cwd, got, want)
				}
			}
		})
	}
}

func TestQR20PythonExecutablePrefersApplicationOverCallerEnvironment(t *testing.T) {
	t.Setenv("DEVSECOPS_PYTHON", "")
	t.Setenv("VIRTUAL_ENV", "")
	root, caller := t.TempDir(), t.TempDir()
	want := filepath.Join(root, ".venv", "bin", "python")
	writePythonFixture(t, want)
	writePythonFixture(t, filepath.Join(caller, ".venv", "bin", "python"))
	if got := pythonExecutableAt(filepath.Join(root, "bin", "devsecops-agent-go"), caller, "linux"); got != want {
		t.Fatalf("python = %q, want the application's %q", got, want)
	}
}

func TestQR20ExplicitPythonOverrideIsAuthoritative(t *testing.T) {
	want := filepath.Join(t.TempDir(), "chosen environment", "python")
	t.Setenv("DEVSECOPS_PYTHON", want)
	if got := pythonExecutableAt("", t.TempDir(), "linux"); got != want {
		t.Fatalf("python = %q, want explicit override %q", got, want)
	}
}

func TestQR20PythonExecutableUsesActiveEnvironment(t *testing.T) {
	t.Setenv("DEVSECOPS_PYTHON", "")
	venv := t.TempDir()
	t.Setenv("VIRTUAL_ENV", venv)
	want := filepath.Join(venv, "bin", "python")
	writePythonFixture(t, want)
	if got := pythonExecutableAt("", t.TempDir(), "linux"); got != want {
		t.Fatalf("python = %q, want active environment %q", got, want)
	}
}

func TestQR20PythonExecutableSupportsPython3OnPATH(t *testing.T) {
	t.Setenv("DEVSECOPS_PYTHON", "")
	t.Setenv("VIRTUAL_ENV", "")
	bin := t.TempDir()
	name := "python3"
	if runtime.GOOS == "windows" {
		name += ".exe"
		t.Setenv("PATHEXT", ".EXE")
	}
	want := filepath.Join(bin, name)
	writePythonFixture(t, want)
	t.Setenv("PATH", bin)
	if got := pythonExecutableAt("", t.TempDir(), "linux"); got != want {
		t.Fatalf("python = %q, want PATH's %q", got, want)
	}
}

func TestQR20PythonExecutablePreservesVenvSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX virtual environments use interpreter symlinks")
	}
	t.Setenv("DEVSECOPS_PYTHON", "")
	t.Setenv("VIRTUAL_ENV", "")
	root := t.TempDir()
	base := filepath.Join(root, "system-python")
	writePythonFixture(t, base)
	want := filepath.Join(root, ".venv", "bin", "python")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, want); err != nil {
		t.Fatal(err)
	}
	if got := pythonExecutableAt(filepath.Join(root, "bin", "devsecops-agent-go"), t.TempDir(), "linux"); got != want {
		t.Fatalf("python = %q, want virtual-environment symlink %q", got, want)
	}
}

func writePythonFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("test interpreter"), 0o755); err != nil {
		t.Fatal(err)
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
