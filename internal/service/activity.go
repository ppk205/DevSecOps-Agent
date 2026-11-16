package service

import (
	"context"
	"encoding/json"

	"devsecops-agent/internal/bridge"
)

// RunActivity đọc các chẩn đoán được giữ lại mà không cần tải các finding nặng về bằng chứng.
// FR-71, DR-09 và IR-16 yêu cầu lịch sử phải nhận diện lượt chạy và sự kiện của chính nó.
type RunActivity struct {
	RunSummary
	Events []bridge.Event `json:"events"`
	Result map[string]any `json:"result"`
}

func (s *Store) Activity(ctx context.Context, id string) (RunActivity, error) {
	info, err := s.Summary(ctx, id)
	if err != nil {
		return RunActivity{}, err
	}
	var events, result string
	err = s.DB.QueryRowContext(ctx, `SELECT events_json, json_object(
		'run_id', coalesce(public_id,cast(id as text)), 'status', status,
		'gate', json_extract(result_json,'$.gate'),
		'exit_code', json_extract(result_json,'$.exit_code'),
		'findings', (SELECT count(*) FROM findings WHERE run_id=runs.id),
		'errors', json_extract(result_json,'$.errors'),
		'ai_usage', json_extract(result_json,'$.ai_usage'),
		'ai_assessment_count', json_array_length(result_json,'$.assessments'),
		'reports', json_extract(result_json,'$.reports'),
		'summary_path', json_extract(result_json,'$.summary_path'))
		FROM runs WHERE id=?`, info.ID).Scan(&events, &result)
	if err != nil {
		return RunActivity{}, err
	}
	activity := RunActivity{RunSummary: info}
	if err = json.Unmarshal([]byte(events), &activity.Events); err != nil {
		return RunActivity{}, err
	}
	err = json.Unmarshal([]byte(result), &activity.Result)
	return activity, err
}

func (b *Backend) Activity(ctx context.Context, id string) (RunActivity, error) {
	return b.Store.Activity(ctx, id)
}
