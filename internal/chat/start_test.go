package chat

import (
	tea "charm.land/bubbletea/v2"
	"strings"
	"testing"
)

func models(m Model, local, key bool) Model {
	return step(m, event("models", map[string]any{"items": []map[string]any{{"alias": "my-model", "models": []string{"small", "large"}, "default_model": "small", "local": local, "key_set": key}}}))
}
func TestStartScreenShowsKeyStatusNeverValue(t *testing.T) {
	m, _ := setup()
	m = models(m, false, false)
	view := m.View().Content
	if !strings.Contains(view, "my-model · key missing") || !strings.Contains(view, "[ Set key ]") || strings.Contains(view, "DEVSEC_KEY_") {
		t.Fatal(view)
	}
}
func TestAddModelFormMasksKeyAndSendsModelAdd(t *testing.T) {
	m, h := setup()
	m = click(m, "model:add")
	for i, v := range []string{"local-test", "Custom", "openai_compatible", "http://127.0.0.1:11434/v1", "small,large", "fixture-not-a-real-key"} {
		m.form.fields[i].SetValue(v)
	}
	view := m.View().Content
	if strings.Contains(view, "fixture-not-a-real-key") || !strings.Contains(view, "•••") {
		t.Fatal(view)
	}
	m = click(m, "form:submit")
	if len(h.sent) != 1 || h.sent[0]["type"] != "model_add" || h.sent[0]["key"] != "fixture-not-a-real-key" {
		t.Fatal("model_add not relayed")
	}
	if m.form != nil {
		t.Fatal("secret form not cleared")
	}
}
func TestEmptyModelListShowsAddModelFirst(t *testing.T) {
	m, _ := setup()
	if m.startFocus != 3 || m.startReason() == "" {
		t.Fatal("empty model start state")
	}
}
func TestStartDisabledUntilTargetAndKeyOK(t *testing.T) {
	m, h := setup()
	m = models(m, false, false)
	m.target.SetValue("project")
	m = click(m, "start")
	if len(h.sent) != 0 {
		t.Fatal("started without key")
	}
	m = models(m, false, true)
	m.target.SetValue("")
	m = click(m, "start")
	if len(h.sent) != 0 {
		t.Fatal("started without target")
	}
}
func TestModelListMarksLocal(t *testing.T) {
	m, _ := setup()
	m = models(m, true, false)
	if !strings.Contains(m.View().Content, "local") {
		t.Fatal("local not shown")
	}
}
func TestStartSendsStartMessage(t *testing.T) {
	m, h := setup()
	m = models(m, true, false)
	m.target.SetValue("project")
	m = click(m, "start")
	if len(h.sent) != 1 || h.sent[0]["type"] != "start" || h.sent[0]["target"] != "project" || h.sent[0]["model"] != "my-model:small" || h.sent[0]["mode"] != "ask" {
		t.Fatal(h.sent)
	}
}
func TestKeysTabSetAndRemoveByKeyboard(t *testing.T) {
	m, h := setup()
	m = models(m, true, false)
	m = click(m, "tab:2")
	m = click(m, "key:my-model")
	m.form.fields[0].SetValue("fixture-secret")
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 1 || h.sent[0]["type"] != "model_key" || strings.Contains(m.View().Content, "fixture-secret") {
		t.Fatal("key not saved safely")
	}
	m = click(m, "remove:my-model")
	if len(h.sent) != 2 || h.sent[1]["type"] != "model_remove" {
		t.Fatal("remove not relayed")
	}
}

func TestTemplateCanBeChosenByMouseAndOverridesRemainEditable(t *testing.T) {
	m, h := setup()
	m = step(m, event("models", map[string]any{"items": []any{}, "templates": []map[string]any{{"id": "fixture-template", "label": "Fixture template", "protocol": "anthropic_messages", "base_url": "https://fixture.invalid", "models": []string{"fixture"}}}}))
	m = click(m, "model:add")
	m = click(m, "form:field:1")
	if m.form.fields[1].Value() != "Fixture template" || m.form.fields[2].Value() != "anthropic_messages" || m.form.fields[3].Value() != "https://fixture.invalid" {
		t.Fatal("template was not selected/prefilled")
	}
	m = click(m, "form:field:3")
	m.form.fields[3].SetValue("http://localhost:1234/v1")
	if !strings.Contains(m.View().Content, "localhost:1234") {
		t.Fatal("custom override not visible")
	}
	m.form.fields[0].SetValue("my-model")
	m.form.fields[4].SetValue("chosen-id")
	m = click(m, "form:submit")
	if len(h.sent) != 1 || h.sent[0]["template"] != "fixture-template" || h.sent[0]["model_protocol"] != "anthropic_messages" {
		t.Fatal("template id/protocol not relayed")
	}
}

func TestStartAndKeysShowHostErrors(t *testing.T) {
	for _, tab := range []int{tabChat, tabKeys} {
		m, _ := setup()
		m.tab = tab
		m = step(m, event("error", map[string]any{"message": "model operation failed"}))
		if !strings.Contains(m.View().Content, "model operation failed") {
			t.Fatal("host error hidden")
		}
	}
}

func TestStartUsesHostDefaultModelAndKeepsSelectionOnKeyRefresh(t *testing.T) {
	m, _ := setup()
	update := event("models", map[string]any{"items": []map[string]any{{"alias": "local", "models": []string{"small", "large"}, "default_model": "large", "local": true}}})
	m = step(m, update)
	if m.modelSpec() != "local:large" {
		t.Fatal("host default_model ignored")
	}
	m.cycleModel(-1)
	m = step(m, update)
	if m.modelSpec() != "local:small" {
		t.Fatal("models refresh reset human selection")
	}
}

func TestStartPendingListIsKeyboardReachable(t *testing.T) {
	m, h := setup()
	m = step(m, event("pending", map[string]any{"items": []map[string]any{{"id": "p", "ref": "abc", "files": []string{"A.java"}}}}))
	m = press(m, tea.KeyTab)
	m = press(m, tea.KeyTab)
	m = press(m, tea.KeyEnter)
	if len(h.sent) != 1 || h.sent[0]["name"] != "pending" {
		t.Fatal("Tab/Enter cannot reach pending review")
	}
}
