package service

import "context"

// Notifications are trusted operator actions; they are never model-callable tools.
type NotificationChannel struct {
	Enabled    bool     `json:"enabled"`
	Events     []string `json:"events"`
	TokenEnv   string   `json:"token_env,omitempty"`
	ChatEnv    string   `json:"chat_env,omitempty"`
	WebhookEnv string   `json:"webhook_env,omitempty"`
}
type NotificationSettings struct {
	SchemaVersion int                 `json:"schema_version"`
	Mode          string              `json:"mode"`
	Telegram      NotificationChannel `json:"telegram"`
	Discord       NotificationChannel `json:"discord"`
}
type NotificationEvent struct {
	Kind    string `json:"kind"`
	Label   string `json:"label"`
	Message string `json:"message"`
}
type NotificationDelivery struct {
	Channel string              `json:"channel"`
	Status  string              `json:"status"`
	Detail  string              `json:"detail"`
	Events  []NotificationEvent `json:"events"`
}
type NotificationResponse struct {
	Settings   *NotificationSettings  `json:"settings,omitempty"`
	RunID      string                 `json:"run_id"`
	Mode       string                 `json:"mode"`
	Status     string                 `json:"status"`
	Detail     string                 `json:"detail"`
	Deliveries []NotificationDelivery `json:"deliveries"`
}

func (b *Backend) Notification(ctx context.Context, params map[string]any) (NotificationResponse, error) {
	var response NotificationResponse
	err := b.Client.Call(ctx, "notification", params, &response, nil)
	return response, err
}
