package tui

import (
	"encoding/json"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"devsecops-agent/internal/service"
)

func TestFR48ModelControlsAreVisibleAndPartOfReviewSignature(t *testing.T) {
	m, _ := readyWorkflow(t)
	if len(m.inputs) <= 12 {
		t.Fatal("the native workspace has no AI mode control")
	}
	before := m.signature()
	m.inputs[12].SetValue("hunt")
	if before == m.signature() {
		t.Fatal("changing AI mode did not invalidate the reviewed configuration")
	}
	if !strings.Contains(m.formView(), "Scan mode") {
		t.Fatal("AI mode is hidden from the main workspace")
	}
}

func TestFR48ProfileSelectionDisplaysKeyStatusAndUsesConfiguredAlias(t *testing.T) {
	m, _ := readyWorkflow(t)
	m.modelProfiles = []service.ModelProfile{{ID: "test-profile", DefaultModel: "test-model", KeySet: true}}
	m.field = aiModeControl
	m = press(m, tea.KeyPressMsg{Code: tea.KeyRight})
	m.field = providerControl
	m = press(m, tea.KeyPressMsg{Code: tea.KeyRight})
	cfg, err := m.config()
	if err != nil || !cfg.AIEnabled() || cfg.ProviderProfile == nil || *cfg.ProviderProfile != "test-profile" {
		t.Fatal("profile selection did not reach the scan configuration")
	}
	if !strings.Contains(m.modelHint(), "key set") || !strings.Contains(m.modelHint(), "test-model") {
		t.Fatal("model metadata is not visible")
	}
}

func TestFR48FindingExplanationKeepsProposalSeparateFromFindingStatus(t *testing.T) {
	payload := json.RawMessage(`{"title":"Finding","status":"unprocessed","metadata":{"ai_assessments":[{"provider_id":"test-profile","model_id":"test-model","proposed_status":"unresolved","rationale":"Retained explanation: evidence is incomplete"}]}}`)
	detail, err := describeFinding(payload)
	if err != nil || !strings.Contains(detail.text, "Retained explanation") || !strings.Contains(detail.text, "Model proposal: unresolved") || !strings.Contains(detail.text, "Verification / review: unprocessed") {
		t.Fatal("the explanation or its status boundary is missing")
	}
}

func TestFR49UsageDoesNotInventUnknownTokensOrCost(t *testing.T) {
	text := strings.Join(resultText(map[string]any{"ai_usage": map[string]any{"requests": 1, "failed_requests": 1, "total_tokens": nil}}), "\n")
	if !strings.Contains(text, "tokens unavailable") || !strings.Contains(text, "cost unavailable") {
		t.Fatal("unknown model accounting appeared as zero or a known price")
	}
}

func TestFR71AIReviewShowsTheActualSelectedScannerSubset(t *testing.T) {
	cfg := service.Defaults()
	cfg.Tools = []string{"native-hunt"}
	text := reviewSummary("source", cfg, map[string]any{})
	if !strings.Contains(text, "Scanners: native-hunt") || strings.Contains(text, "Semgrep") {
		t.Fatal("review advertised scanners outside the selected subset")
	}
}

func TestQR21ModelControlsKeepHiddenKeyEntryVisibleAtSmallSizes(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {75, 26}} {
		m, _ := readyWorkflow(t)
		updated, _ := m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m = updated.(Model)
		m.inputs[aiModeControl].SetValue("hunt")
		m.keyInput, m.keysFocus = true, 1
		m.keysValue.Focus()
		if !strings.Contains(m.formView(), "Value (hidden)") {
			t.Fatalf("%dx%d: model controls pushed the focused key field off screen", size[0], size[1])
		}
	}
}
