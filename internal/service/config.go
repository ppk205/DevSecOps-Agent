package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
	_ "time/tzdata"
)

type Config struct {
	SchemaVersion  int     `json:"schema_version"`
	Profile        string  `json:"profile"`
	FailOn         string  `json:"fail_on"`
	OutputDir      string  `json:"output_dir"`
	Timezone       string  `json:"timezone"`
	Timeout        int     `json:"timeout"`
	MaxFiles       int     `json:"max_files"`
	AllowDirty     bool    `json:"allow_dirty"`
	CI             bool    `json:"ci"`
	Laya           bool    `json:"laya"`
	LayaConfigPath *string `json:"laya_config_path"`
}

func Defaults() Config {
	return Config{SchemaVersion: 1, Profile: "fast", FailOn: "high", OutputDir: "artifacts", Timezone: "Asia/Saigon", Timeout: 600, MaxFiles: 100000}
}
func Resolve(profile, path string, flags map[string]any) (Config, error) {
	cfg := Defaults()
	values := map[string]any{}
	data, _ := json.Marshal(cfg)
	_ = json.Unmarshal(data, &values)
	if profile != "" {
		values["profile"] = profile
		if profile == "full" {
			values["timeout"] = 3600
		}
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		var file map[string]any
		if err = json.Unmarshal(data, &file); err != nil {
			return cfg, err
		}
		if file == nil || file["schema_version"] != float64(1) {
			return cfg, fmt.Errorf("configuration must be an object with schema_version: 1")
		}
		for k, v := range file {
			values[k] = v
		}
	}
	for k, v := range flags {
		if v != nil {
			values[k] = v
		}
	}
	data, _ = json.Marshal(values)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid scan configuration: %w", err)
	}
	if cfg.SchemaVersion != 1 || cfg.Profile != "fast" && cfg.Profile != "full" || cfg.Timeout < 1 || cfg.Timeout > 86400 || cfg.MaxFiles < 1 {
		return cfg, fmt.Errorf("invalid scan configuration")
	}
	if !map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true, "none": true}[cfg.FailOn] {
		return cfg, fmt.Errorf("invalid fail_on threshold")
	}
	if _, err := time.LoadLocation(cfg.Timezone); err != nil {
		return cfg, fmt.Errorf("unknown display timezone")
	}
	return cfg, nil
}
