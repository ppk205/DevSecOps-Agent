package service

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDR09HistoryActivityRetainsEventsFailuresAndReports(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "activity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.DB.Exec(`CREATE TABLE runs(id INTEGER PRIMARY KEY, public_id TEXT,status TEXT,attempt INTEGER,created_at TEXT,findings_revision INTEGER,events_json TEXT,result_json TEXT);
	CREATE TABLE findings(id INTEGER PRIMARY KEY,run_id INTEGER);
	INSERT INTO findings VALUES(1,1),(2,2);
	INSERT INTO runs VALUES(1,'run-a','failed',1,'2026-10-03T00:00:00Z',1,'[{"run_id":"run-a","stage":"semgrep","status":"completed"}]','{"gate":"failed","exit_code":2,"findings":1,"errors":["disk full"],"reports":{"json":"retained.json"}}');`)
	if err != nil {
		t.Fatal(err)
	}
	activity, err := store.Activity(context.Background(), "run-a")
	if err != nil {
		t.Fatal(err)
	}
	if activity.RunID != "run-a" || activity.Events[0].Stage != "semgrep" || activity.Result["errors"].([]any)[0] != "disk full" || activity.Result["reports"].(map[string]any)["json"] != "retained.json" {
		t.Fatal("retained diagnostics were missing or belonged to another run")
	}
	if activity.Result["findings"] != float64(1) {
		t.Fatal("activity counted findings from another run")
	}
}
