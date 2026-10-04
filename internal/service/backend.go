package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"devsecops-agent/internal/bridge"
)

// Backend keeps one scan execution owner. Reads, filtering, and configuration
// are native Go; audited scanner and report implementations remain in Python.
type Backend struct {
	Client  *bridge.Client
	Store   *Store
	DBPath  string
	Version string
	mu      sync.Mutex
	runMu   sync.Mutex
}

func (b *Backend) Init(ctx context.Context) error {
	var info map[string]any
	if err := b.Client.Call(ctx, "hello", map[string]any{}, &info, nil); err != nil {
		return err
	}
	if path, ok := info["db_path"].(string); ok {
		b.DBPath = path
	}
	b.Version, _ = info["version"].(string)
	store, err := OpenStore(b.DBPath)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.Store = store
	b.mu.Unlock()
	return nil
}
func (b *Backend) Close() {
	b.Client.Close()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Store != nil {
		_ = b.Store.Close()
	}
}
func (b *Backend) History(ctx context.Context) ([]RunSummary, error) { return b.Store.History(ctx) }
func (b *Backend) Findings(ctx context.Context, id, query string, offset int) (FindingPage, error) {
	return b.Store.Findings(ctx, id, query, offset, 200)
}
func (b *Backend) Finding(ctx context.Context, id, findingID string) (json.RawMessage, error) {
	return b.Store.Finding(ctx, id, findingID)
}
func (b *Backend) Review(ctx context.Context, checkout string, config Config) (map[string]any, error) {
	var result map[string]any
	err := b.Client.Call(ctx, "review", map[string]any{"checkout": checkout, "workdir": "harness", "commit": "", "configuration": config}, &result, nil)
	return result, err
}
func (b *Backend) Run(ctx context.Context, params map[string]any, event func(bridge.Event)) (map[string]any, error) {
	return b.nativeRun(ctx, params, event)
}

func (b *Backend) PythonRun(ctx context.Context, params map[string]any, event func(bridge.Event)) (map[string]any, error) {
	var result map[string]any
	err := b.Client.Call(ctx, "run", params, &result, event)
	if err == nil {
		if ref, ok := result["result_ref"].(string); ok {
			var data []byte
			data, err = os.ReadFile(ref)
			if err == nil {
				err = json.Unmarshal(data, &result)
			}
		}
	}
	return result, err
}
func (b *Backend) Retry(ctx context.Context, id string, event func(bridge.Event)) (map[string]any, error) {
	var prior map[string]any
	if err := b.Client.Call(ctx, "detail", map[string]any{"run_id": id}, &prior, nil); err != nil {
		return nil, err
	}
	if prior["status"] == "running" || prior["status"] == "queued" {
		return nil, fmt.Errorf("cannot retry an active scan")
	}
	spec := obj(prior["spec"])
	metadata := obj(spec["metadata"])
	return b.nativeRun(ctx, map[string]any{"checkout": spec["repository_checkout_path"], "repo": spec["target_repository_url"], "commit": spec["target_commit_sha"], "configuration": metadata["configuration"], "parent_id": intNumber(prior["id"])}, event)
}
func (b *Backend) Cancel(ctx context.Context, id string) error { return b.Store.Cancel(ctx, id) }
func (b *Backend) Export(ctx context.Context, id, format, output string) (string, error) {
	var result struct {
		Path string `json:"path"`
	}
	err := b.Client.Call(ctx, "export", map[string]any{"run_id": id, "format": format, "output": output}, &result, nil)
	return result.Path, err
}
func (b *Backend) Capabilities(ctx context.Context) ([]map[string]any, error) {
	var result []map[string]any
	err := b.Client.Call(ctx, "capabilities", map[string]any{}, &result, nil)
	return result, err
}
