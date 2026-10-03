package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"devsecops-agent/internal/analysis"
	"devsecops-agent/internal/bridge"
)

func utcStamp() string         { return time.Now().UTC().Format("2006-01-02T15:04:05.999999+00:00") }
func marshal(value any) string { data, _ := json.Marshal(value); return string(data) }
func searchable(value any) string {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return strings.ToLower(buffer.String())
}
func (s *Store) AddRun(ctx context.Context, publicID string, spec map[string]any, parentID int) (int, int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	stamp := utcStamp()
	target, err := tx.ExecContext(ctx, "INSERT INTO targets(repository_url,commit_sha,created_at) VALUES(?,?,?)", spec["target_repository_url"], spec["target_commit_sha"], stamp)
	if err != nil {
		return 0, 0, err
	}
	targetID, err := target.LastInsertId()
	if err != nil {
		return 0, 0, err
	}
	attempt := 1
	var parent any
	if parentID > 0 {
		parent = parentID
		var previous int
		if err = tx.QueryRowContext(ctx, "SELECT attempt FROM runs WHERE id=?", parentID).Scan(&previous); err != nil {
			return 0, 0, err
		}
		attempt = previous + 1
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO runs(target_id,attempt,status,scan_spec_json,public_id,parent_id,result_json,events_json,cancel_requested,findings_revision,created_at,updated_at) VALUES(?,?,'running',?,?,?,'{}','[]',0,0,?,?)", targetID, attempt, marshal(spec), publicID, parent, stamp, stamp)
	if err != nil {
		return 0, 0, err
	}
	pk, err := result.LastInsertId()
	if err != nil {
		return 0, 0, err
	}
	return int(pk), attempt, tx.Commit()
}
func (s *Store) Persist(ctx context.Context, pk int, spec, result map[string]any, events []bridge.Event, findings []analysis.Object) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE runs SET events_json=?,scan_spec_json=?,result_json=?,updated_at=? WHERE id=?", marshal(events), marshal(spec), marshal(result), utcStamp(), pk); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE targets SET commit_sha=? WHERE id=(SELECT target_id FROM runs WHERE id=?)", spec["target_commit_sha"], pk); err != nil {
		return err
	}
	event := events[len(events)-1]
	var stageID int
	err = tx.QueryRowContext(ctx, "SELECT id FROM stages WHERE run_id=? AND name=? LIMIT 1", pk, event.Stage).Scan(&stageID)
	var completed any
	if event.Status != "running" {
		completed = event.Timestamp
	}
	if err == sql.ErrNoRows {
		_, err = tx.ExecContext(ctx, "INSERT INTO stages(run_id,name,status,ordinal,started_at,completed_at,error_message) VALUES(?,?,?,?,?,?,?)", pk, event.Stage, event.Status, event.Sequence, event.Timestamp, completed, event.Message)
	} else if err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE stages SET status=?,completed_at=?,error_message=? WHERE id=?", event.Status, completed, event.Message, stageID)
	}
	if err != nil {
		return err
	}
	type savedFinding struct {
		pk      int
		payload string
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,finding_id,finding_json FROM findings WHERE run_id=? ORDER BY id DESC", pk)
	if err != nil {
		return err
	}
	saved := map[string]savedFinding{}
	for rows.Next() {
		var id int
		var fid sql.NullString
		var payload string
		if err = rows.Scan(&id, &fid, &payload); err != nil {
			rows.Close()
			return err
		}
		saved[fid.String] = savedFinding{id, payload}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	changed := false
	for _, finding := range findings {
		fid := fmt.Sprint(finding["finding_id"])
		payload := marshal(finding)
		old, exists := saved[fid]
		delete(saved, fid)
		if exists && old.payload == payload {
			continue
		}
		summary := FindingSummary{FindingID: fid, Severity: fmt.Sprint(finding["severity"]), CWE: fmt.Sprint(finding["cwe_category"]), Status: fmt.Sprint(finding["status"]), Scanner: analysis.CSVTools(finding), Title: fmt.Sprint(finding["title"])}
		search := searchable(finding)
		if exists {
			_, err = tx.ExecContext(ctx, "UPDATE findings SET finding_json=?,summary_json=?,search_text=? WHERE id=?", payload, marshal(summary), search, old.pk)
		} else {
			_, err = tx.ExecContext(ctx, "INSERT INTO findings(run_id,finding_json,finding_id,summary_json,search_text,created_at) VALUES(?,?,?,?,?,?)", pk, payload, fid, marshal(summary), search, utcStamp())
		}
		if err != nil {
			return err
		}
		changed = true
	}
	for _, old := range saved {
		if _, err = tx.ExecContext(ctx, "DELETE FROM findings WHERE id=?", old.pk); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if _, err = tx.ExecContext(ctx, "UPDATE runs SET findings_revision=findings_revision+1 WHERE id=?", pk); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) Finish(ctx context.Context, pk int, summary map[string]any) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE runs SET status=?,result_json=?,updated_at=? WHERE id=?", summary["status"], marshal(summary), utcStamp(), pk); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE stages SET status=?,completed_at=? WHERE run_id=? AND status='running'", summary["status"], utcStamp(), pk)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) CancelRequested(ctx context.Context, pk int) (bool, error) {
	var flag int
	err := s.DB.QueryRowContext(ctx, "SELECT cancel_requested FROM runs WHERE id=?", pk).Scan(&flag)
	return flag != 0, err
}
