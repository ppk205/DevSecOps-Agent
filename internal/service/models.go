package service

import "context"

// ModelProfile contains display metadata and a key-status flag, never credentials.
type ModelProfile struct {
	ID           string   `json:"id"`
	Label        string   `json:"label"`
	Models       []string `json:"models"`
	DefaultModel string   `json:"default_model"`
	KeySet       bool     `json:"key_set"`
}

func (b *Backend) ModelProfiles(ctx context.Context) ([]ModelProfile, error) {
	var result struct {
		Profiles []ModelProfile `json:"profiles"`
	}
	err := b.Client.Call(ctx, "model_profiles", map[string]any{}, &result, nil)
	return result.Profiles, err
}
