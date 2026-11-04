package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestDR09FindingLoadsOnlyItsOwnPersistedAIAssessment(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ai.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.DB.Exec(`CREATE TABLE runs(id INTEGER PRIMARY KEY,public_id TEXT,status TEXT,attempt INTEGER,created_at TEXT,findings_revision INTEGER,result_json TEXT);
	CREATE TABLE findings(id INTEGER PRIMARY KEY,run_id INTEGER,finding_id TEXT,finding_json TEXT);
	INSERT INTO runs VALUES(1,'run-a','completed',1,'2026-11-04',1,'{"assessments":[{"finding_id":"a","rationale":"matching explanation"},{"finding_id":"b","rationale":"other finding"}]}');
	INSERT INTO findings VALUES(1,1,'a','{"finding_id":"a","metadata":{}}');`)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := store.Finding(context.Background(), "run-a", "a")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	_ = json.Unmarshal(payload, &result)
	assessments := result["metadata"].(map[string]any)["ai_assessments"].([]any)
	if len(assessments) != 1 || assessments[0].(map[string]any)["rationale"] != "matching explanation" {
		t.Fatal("the finding displayed another finding's explanation")
	}
}
