package service

import (
	"encoding/json"
	"testing"
)

func TestNotificationSettingsPreserveWebhookOnRoundTrip(t *testing.T) {
	input := []byte(`{"schema_version":2,"mode":"manual","telegram":{"enabled":false,"events":[]},"discord":{"enabled":false,"events":[]},"webhook":{"enabled":true,"events":["scan_completed"],"url_env":"CUSTOM_URL","signing_key_env":"CUSTOM_KEY","allowed_hosts":["hooks.example.com"]}}`)
	var settings NotificationSettings
	if err := json.Unmarshal(input, &settings); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	channel, ok := result["webhook"].(map[string]any)
	if !ok || channel["enabled"] != true || channel["url_env"] != "CUSTOM_URL" || channel["signing_key_env"] != "CUSTOM_KEY" {
		t.Fatalf("webhook lost: %s", encoded)
	}
	if hosts, ok := channel["allowed_hosts"].([]any); !ok || len(hosts) != 1 || hosts[0] != "hooks.example.com" {
		t.Fatalf("hosts lost: %s", encoded)
	}
}
