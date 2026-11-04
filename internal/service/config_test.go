package service

import (
	"encoding/json"
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

func TestFR48NativeConfigurationAcceptsExplicitModelSupport(t *testing.T) {
	cfg, err := Resolve("fast", "", map[string]any{
		"mode": "hunt", "provider_profile": "test-profile", "provider_model": "test-model",
		"ai_review": true, "ai_report": true, "max_ai_findings": 3,
		"tools": []string{"native-hunt"},
	})
	if err != nil {
		t.Fatalf("native configuration rejected model settings: %v", err)
	}
	data, _ := json.Marshal(cfg)
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	if fields["mode"] != "hunt" || fields["provider_model"] != "test-model" || fields["max_ai_findings"] != float64(3) {
		t.Fatal("model settings were not retained")
	}
	defaults, _ := json.Marshal(Defaults())
	_ = json.Unmarshal(defaults, &fields)
	if fields["mode"] != "deterministic" || fields["ai_review"] != false || fields["ai_report"] != false {
		t.Fatal("native defaults enabled model calls without an explicit selection")
	}
}

func TestFR48BlankProviderOverrideRestoresAutomaticSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"provider_profile":"stored-profile"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Resolve("fast", path, map[string]any{"provider_profile": ""})
	if err != nil || cfg.ProviderProfile != nil {
		t.Fatal("an explicit automatic-provider selection retained the file's profile")
	}
}
