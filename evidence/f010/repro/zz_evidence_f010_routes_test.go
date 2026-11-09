package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
)

// F-010 evidence: prompt and trigger management are operator routes behind the
// JWT boundary, not tools target content can call. The preview route accepts an
// arbitrary template but deliberately does not persist it; only an authenticated
// PUT does. A trigger can only be persisted for a custom agent, again by an
// authenticated operator request.
func TestF010PromptAndTriggerManagementRoutes(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatal("missing worker", err)
	}
	oldPrompt, _ := pg.CurrentPrompt(worker.ID)
	t.Cleanup(func() { _, _ = pg.SavePrompt(worker.ID, oldPrompt, "restore F-010 fixture", "test") })

	unauth := httptest.NewRequest(http.MethodPut, "/api/agents/worker/prompt", strings.NewReader(`{"template":"UNAUTH_MARKER"}`))
	unauth.Header.Set("Content-Type", "application/json")
	uw := httptest.NewRecorder()
	s.Handler().ServeHTTP(uw, unauth)

	preview := request("POST", "/api/agents/worker/prompt/preview", `{"template":"F010_PREVIEW_MARKER {{.Now}}"}`)
	afterPreview, _ := pg.CurrentPrompt(worker.ID)
	previewPersisted := strings.Contains(afterPreview, "F010_PREVIEW_MARKER")

	saved := request("PUT", "/api/agents/worker/prompt", `{"template":"F010_PROMPT_MARKER {{.Now}}","note":"F-010 probe"}`)
	afterSave, _ := pg.CurrentPrompt(worker.ID)
	promptSaved := saved.Code == http.StatusOK && strings.Contains(afterSave, "F010_PROMPT_MARKER")

	builtinTrigger := request("POST", "/api/agents/worker/triggers", `{"enabled":true,"on_task_create":true,"task_create_message":"F010_TRIGGER_MARKER"}`)
	key := fmt.Sprintf("f010_agent_%d", time.Now().UnixNano())
	if _, err := pg.CreateAgent(key, "F-010 probe", "management route probe"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTriggersForAgent(key); _ = pg.DeleteAgent(key) })
	customTrigger := request("POST", "/api/agents/"+key+"/triggers", `{"enabled":true,"on_task_create":true,"task_create_message":"F010_TRIGGER_MARKER"}`)
	triggers, _ := pg.ListTriggersFor(key)
	triggerSaved := customTrigger.Code == http.StatusOK && len(triggers) == 1 && strings.Contains(triggers[0].TaskCreateMessage, "F010_TRIGGER_MARKER")

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{})
	tools, _, cleanup := agent.AugmentTools(ctx, "worker", nil)
	defer cleanup()
	agentRouteTool := false
	for _, tool := range tools {
		if strings.Contains(tool.Name(), "prompt") || strings.Contains(tool.Name(), "trigger") {
			agentRouteTool = true
		}
	}

	fmt.Printf("F010 prompt_unauth=%d preview_status=%d preview_persisted=%v prompt_saved=%v builtin_trigger=%d custom_trigger_saved=%v agent_route_tool=%v\n",
		uw.Code, preview.Code, previewPersisted, promptSaved, builtinTrigger.Code, triggerSaved, agentRouteTool)

	if uw.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated prompt route = %d, want 401", uw.Code)
	}
	if preview.Code != http.StatusOK || previewPersisted {
		t.Fatalf("preview route persisted template: status=%d persisted=%v", preview.Code, previewPersisted)
	}
	if !promptSaved {
		t.Fatalf("authenticated prompt save failed: status=%d current=%q", saved.Code, afterSave)
	}
	if builtinTrigger.Code != http.StatusBadRequest {
		t.Fatalf("built-in trigger route = %d, want 400", builtinTrigger.Code)
	}
	if !triggerSaved {
		t.Fatalf("custom trigger was not persisted: status=%d body=%s triggers=%+v", customTrigger.Code, customTrigger.Body.String(), triggers)
	}
	if agentRouteTool {
		t.Fatal("worker exposes a prompt/trigger management tool")
	}
}
