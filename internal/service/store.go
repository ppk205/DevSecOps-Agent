package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }
type RunSummary struct {
	ID        int    `json:"id"`
	RunID     string `json:"run_id"`
	Status    string `json:"status"`
	Attempt   int    `json:"attempt"`
	CreatedAt string `json:"created_at"`
	Revision  int    `json:"revision"`
}
type FindingSummary struct {
	FindingID string `json:"finding_id"`
	Severity  string `json:"severity"`
	CWE       string `json:"cwe_category"`
	Status    string `json:"status"`
	Scanner   string `json:"scanner"`
	Title     string `json:"title"`
}
type FindingPage struct {
	RunSummary
	Items  []FindingSummary `json:"items"`
	Total  int              `json:"total"`
	Offset int              `json:"offset"`
	Limit  int              `json:"limit"`
}

func OpenStore(path string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.ToSlash(absolute)+"?_pragma=busy_timeout(10000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) History(ctx context.Context) ([]RunSummary, error) {
	return s.history(ctx, 100)
}
func (s *Store) AllHistory(ctx context.Context) ([]RunSummary, error) { return s.history(ctx, 0) }
func (s *Store) history(ctx context.Context, limit int) ([]RunSummary, error) {
	query := "SELECT id, coalesce(public_id,cast(id as text)),status,attempt,created_at,findings_revision FROM runs ORDER BY id DESC"
	if limit > 0 {
		query += " LIMIT " + strconv.Itoa(limit)
	}
	rows, err := s.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RunSummary{}
	for rows.Next() {
		var r RunSummary
		if err = rows.Scan(&r.ID, &r.RunID, &r.Status, &r.Attempt, &r.CreatedAt, &r.Revision); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
func (s *Store) Summary(ctx context.Context, id string) (RunSummary, error) {
	var result RunSummary
	err := s.DB.QueryRowContext(ctx, "SELECT id,coalesce(public_id,cast(id as text)),status,attempt,created_at,findings_revision FROM runs WHERE id=? OR public_id=? ORDER BY id LIMIT 1", id, id).Scan(&result.ID, &result.RunID, &result.Status, &result.Attempt, &result.CreatedAt, &result.Revision)
	return result, err
}
func (s *Store) Findings(ctx context.Context, id, query string, offset, limit int) (FindingPage, error) {
	page := FindingPage{Items: []FindingSummary{}, Offset: offset, Limit: limit}
	if offset < 0 || limit < 1 || limit > 200 {
		return page, fmt.Errorf("invalid finding page")
	}
	info, err := s.Summary(ctx, id)
	if err != nil {
		return page, err
	}
	page.RunSummary = info
	conditions := []string{"run_id=?"}
	args := []any{info.ID}
	fields := map[string]string{"severity": "severity", "cwe": "cwe_category", "status": "status", "scanner": "scanner"}
	for _, term := range strings.Fields(strings.ToLower(query)) {
		column, value := "search_text", term
		if name, rest, found := strings.Cut(term, ":"); found {
			field, ok := fields[name]
			if !ok {
				conditions = append(conditions, "0")
				continue
			}
			column = "lower(json_extract(summary_json,'$." + field + "'))"
			value = rest
		}
		value = strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(value)
		conditions = append(conditions, column+" LIKE ? ESCAPE '\\'")
		args = append(args, "%"+value+"%")
	}
	where := strings.Join(conditions, " AND ")
	if err = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM findings WHERE "+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	args = append(args, limit, offset)
	rows, err := s.DB.QueryContext(ctx, "SELECT summary_json FROM findings WHERE "+where+" ORDER BY id LIMIT ? OFFSET ?", args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		var item FindingSummary
		if err = rows.Scan(&payload); err != nil {
			return page, err
		}
		if err = json.Unmarshal([]byte(payload), &item); err != nil {
			return page, err
		}
		page.Items = append(page.Items, item)
	}
	return page, rows.Err()
}
func (s *Store) Finding(ctx context.Context, id, findingID string) (json.RawMessage, error) {
	info, err := s.Summary(ctx, id)
	if err != nil {
		return nil, err
	}
	var payload string
	err = s.DB.QueryRowContext(ctx, "SELECT finding_json FROM findings WHERE run_id=? AND finding_id=? ORDER BY id LIMIT 1", info.ID, findingID).Scan(&payload)
	return json.RawMessage(payload), err
}
func (s *Store) Cancel(ctx context.Context, id string) error {
	info, err := s.Summary(ctx, id)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, "UPDATE runs SET cancel_requested=1 WHERE id=?", info.ID)
	return err
}
func ID(pk int) string { return strconv.Itoa(pk) }
