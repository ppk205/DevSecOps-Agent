package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"devsecops-agent/internal/analysis"
)

func (s *Store) Counts(ctx context.Context, id string) (map[string]any, error) {
	info, err := s.Summary(ctx, id)
	if err != nil {
		return nil, err
	}
	counts := map[string]any{"version": "0.1.0", "total": 0, "confirmed": 0, "rejected": 0, "unresolved": 0, "unprocessed": 0}
	rows, err := s.DB.QueryContext(ctx, "SELECT json_extract(finding_json,'$.status'),count(*) FROM findings WHERE run_id=? GROUP BY json_extract(finding_json,'$.status')", info.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err = rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		counts["total"] = counts["total"].(int) + count
		if status != "confirmed" && status != "rejected" && status != "unresolved" {
			status = "unprocessed"
		}
		counts[status] = counts[status].(int) + count
	}
	return counts, rows.Err()
}
func (s *Store) RunContext(ctx context.Context, id string) (map[string]any, error) {
	info, err := s.Summary(ctx, id)
	if err != nil {
		return nil, err
	}
	var url, commit string
	if err = s.DB.QueryRowContext(ctx, "SELECT t.repository_url,t.commit_sha FROM targets t JOIN runs r ON r.target_id=t.id WHERE r.id=?", info.ID).Scan(&url, &commit); err != nil {
		return nil, err
	}
	stages := []map[string]any{}
	rows, err := s.DB.QueryContext(ctx, "SELECT name,status,ordinal,started_at,completed_at,error_message FROM stages WHERE run_id=? ORDER BY ordinal,id", info.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, status string
		var ordinal int
		var started, completed, message *string
		if err = rows.Scan(&name, &status, &ordinal, &started, &completed, &message); err != nil {
			rows.Close()
			return nil, err
		}
		stages = append(stages, map[string]any{"name": name, "status": status, "ordinal": ordinal, "started_at": started, "completed_at": completed, "error_message": message})
	}
	rows.Close()
	findings := []analysis.Object{}
	rows, err = s.DB.QueryContext(ctx, "SELECT finding_json FROM findings WHERE run_id=? ORDER BY id LIMIT 200", info.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		var finding analysis.Object
		if err = rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(payload), &finding); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	counts, err := s.Counts(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"run": info, "target": map[string]string{"repository_url": url, "commit_sha": commit}, "stages": stages, "findings": findings, "counts": counts, "finding_count": counts["total"]}, rows.Err()
}
func (s *Store) FindingsContext(ctx context.Context, id, query string, offset int) (map[string]any, error) {
	data, err := s.RunContext(ctx, id)
	if err != nil {
		return nil, err
	}
	page, err := s.Findings(ctx, id, query, offset, 200)
	if err != nil {
		return nil, err
	}
	findings := []analysis.Object{}
	if len(page.Items) > 0 {
		placeholders := []string{}
		args := []any{page.ID}
		for _, item := range page.Items {
			placeholders = append(placeholders, "?")
			args = append(args, item.FindingID)
		}
		rows, err := s.DB.QueryContext(ctx, "SELECT finding_json FROM findings WHERE run_id=? AND finding_id IN("+strings.Join(placeholders, ",")+") ORDER BY id", args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var payload string
			var item analysis.Object
			if err = rows.Scan(&payload); err != nil {
				return nil, err
			}
			if err = json.Unmarshal([]byte(payload), &item); err != nil {
				return nil, err
			}
			findings = append(findings, item)
		}
		if err = rows.Err(); err != nil {
			return nil, err
		}
	}
	data["findings"] = findings
	data["query"] = query
	data["page_total"] = page.Total
	data["next_offset"] = offset + 200
	data["previous_offset"] = max(0, offset-200)
	data["has_next"] = offset+200 < page.Total
	data["has_previous"] = offset > 0
	return data, nil
}
func (s *Store) FindAny(ctx context.Context, id string) (int, json.RawMessage, error) {
	var pk int
	var payload string
	err := s.DB.QueryRowContext(ctx, "SELECT run_id,finding_json FROM findings WHERE finding_id=? ORDER BY id LIMIT 1", id).Scan(&pk, &payload)
	return pk, json.RawMessage(payload), err
}
func (s *Store) SetStatus(ctx context.Context, id, findingID, status string) error {
	if !map[string]bool{"confirmed": true, "rejected": true, "unresolved": true, "unprocessed": true, "pending_validation": true, "triaged": true, "assessed": true}[status] {
		return fmt.Errorf("unknown finding status")
	}
	info, err := s.Summary(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pk int
	var payload, summary string
	if err = tx.QueryRowContext(ctx, "SELECT id,finding_json,summary_json FROM findings WHERE run_id=? AND finding_id=? ORDER BY id LIMIT 1", info.ID, findingID).Scan(&pk, &payload, &summary); err != nil {
		return err
	}
	var finding analysis.Object
	var projected FindingSummary
	if err = json.Unmarshal([]byte(payload), &finding); err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(summary), &projected); err != nil {
		return err
	}
	finding["status"] = status
	projected.Status = status
	if _, err = tx.ExecContext(ctx, "UPDATE findings SET finding_json=?,summary_json=?,search_text=? WHERE id=?", marshal(finding), marshal(projected), searchable(finding), pk); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE runs SET findings_revision=findings_revision+1 WHERE id=?", info.ID); err != nil {
		return err
	}
	return tx.Commit()
}
