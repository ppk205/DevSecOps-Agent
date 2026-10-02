package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestQR21FindingPageLatencyAtTenThousandFindings(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "scale.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.DB.Exec("CREATE TABLE runs(id INTEGER PRIMARY KEY,public_id TEXT,status TEXT,attempt INTEGER,created_at TEXT,findings_revision INTEGER);CREATE TABLE findings(id INTEGER PRIMARY KEY,run_id INTEGER,finding_id TEXT,summary_json TEXT,search_text TEXT,finding_json TEXT);CREATE INDEX findings_run_id ON findings(run_id);INSERT INTO runs VALUES(1,'scale-run','running',1,'2026-10-02T00:00:00+00:00',1)")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare("INSERT INTO findings VALUES(?,1,?,?,?,?)")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10000; i++ {
		summary := FindingSummary{FindingID: fmt.Sprint(i), Severity: "high", CWE: "CWE-89", Status: "unprocessed", Scanner: "semgrep", Title: "SQL injection"}
		payload := marshal(summary)
		if _, err = statement.Exec(i, summary.FindingID, payload, strings.ToLower(payload)+strings.Repeat(" source evidence", 80), payload); err != nil {
			t.Fatal(err)
		}
	}
	statement.Close()
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	samples := []time.Duration{}
	for i := 0; i < 30; i++ {
		started := time.Now()
		page, err := s.Findings(context.Background(), "1", "severity:high source evidence", 200, 200)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 200 || page.Total != 10000 {
			t.Fatal("page lost matching findings")
		}
		samples = append(samples, time.Since(started))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p95 := samples[28]
	t.Logf("10,000 evidence-bearing findings: filtered 200-row page p95 %.3f ms", float64(p95)/float64(time.Millisecond))
	if p95 > 250*time.Millisecond {
		t.Fatalf("finding page exceeds target: %v", p95)
	}
}
