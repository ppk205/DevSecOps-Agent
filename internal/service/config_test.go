package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDR10ConfigPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"timeout":700,"fail_on":"medium"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Resolve("full", path, map[string]any{"timeout": 800})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "full" || cfg.Timeout != 800 || cfg.FailOn != "medium" {
		t.Fatal("defaults/profile/file/flags precedence changed")
	}
	if _, err = Resolve("fast", "", map[string]any{"unknown": true}); err == nil {
		t.Fatal("unknown configuration was accepted")
	}
}
