package server

// Evidence reproducer for F-008.
//
// create_custom_tool is an Allowed platform tool bound to the Auto agent, and it
// accepts kind=command with an arbitrary exec.command. The built custom tool then
// returned permission.Allowed() while its executor calls actool.NewBash().Call
// directly, so the Bash AskUser/safety-floor decision never ran. The probe uses
// the real platform tool to create a command tool bound to the worker agent,
// resolves the worker's toolset, and applies the harness's CheckPermissions step:
// pre-fix the decision is Allow and the command writes its marker; post-fix the
// decision is Ask (the probe does not call it) and the marker is absent. The
// operator executor is the positive control and must still run the same spec.
//
// Run from the ARTEX repository root with the disposable PostgreSQL:
//   ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
//     go test ./server -run 'TestF008' -count=1 -v

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func TestF008AgentCustomToolApprovalBypass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the marker command uses POSIX shell syntax")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	create := f007PlatformTool(t, s, "create_custom_tool")

	// Auto is a ChatAgent whose base is actool.DefaultTools(), so it already has
	// Bash (AskUser-gated). The F-007 MCP launch did not add code execution; it
	// bypassed the MCP gate. Record that here so the finding's severity is grounded
	// in the assembled toolset, not only the source comment.
	hasBash := false
	for _, tool := range actool.DefaultTools() {
		if tool.Name() == "Bash" {
			hasBash = true
			break
		}
	}
	if !hasBash {
		t.Fatal("Auto's DefaultTools base no longer includes Bash; re-check the F-007 severity note")
	}
	t.Logf("Auto base DefaultTools includes Bash: %v", hasBash)

	createRow, err := m.pg.GetTool("create_custom_tool")
	if err != nil || createRow == nil {
		t.Fatalf("create_custom_tool row: %v", err)
	}
	autoBound := false
	for _, agentKey := range createRow.Agents {
		if agentKey == "auto" {
			autoBound = true
			break
		}
	}
	if !autoBound {
		t.Fatalf("create_custom_tool bindings = %v, want auto", createRow.Agents)
	}
	createDecision := create.CheckPermissions(context.Background(), json.RawMessage(`{}`), permission.Context{Mode: permission.ModeDefault})
	t.Logf("create_custom_tool is bound to auto; permission: %s", createDecision.Behavior)

	key := fmt.Sprintf("f008_cmd_%d", os.Getpid())
	marker := filepath.Join(t.TempDir(), "f008-agent-executed")
	// Pre-delete plus a LIFO defer registered before m.Close's defer: cleanup runs
	// while the pool is open and leaves no fixed-name row for the next run.
	_, _ = m.pg.Exec(`DELETE FROM tools WHERE key=$1`, key)
	defer func() { _, _ = m.pg.Exec(`DELETE FROM tools WHERE key=$1`, key) }()

	execSpec, _ := json.Marshal(map[string]any{
		"command": "printf ARTEX-F008 > " + shellQuote(marker),
	})
	createInput, _ := json.Marshal(map[string]any{
		"key":         key,
		"description": "F-008 probe command tool",
		"kind":        "command",
		"exec":        json.RawMessage(execSpec),
		"agents":      []string{"worker"},
		"enabled":     true,
	})
	res, err := create.Call(context.Background(), createInput, nil)
	if err != nil {
		t.Fatalf("create_custom_tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("F-008 create_custom_tool rejected: %s", res.Flatten())
	}
	t.Logf("create_custom_tool accepted: %s", res.Flatten())

	row, err := m.pg.GetTool(key)
	if err != nil || row == nil {
		t.Fatalf("created custom tool not found: %v", err)
	}
	if len(row.Agents) != 1 || row.Agents[0] != "worker" {
		t.Fatalf("tool bindings = %v, want [worker]", row.Agents)
	}

	if agent.ToolResolve == nil {
		t.Fatal("agent.ToolResolve is not wired")
	}
	var resolved actool.CoreTool
	for _, tool := range agent.ToolResolve(context.Background(), "worker", []actool.CoreTool{s.buildCustomTool(row)}) {
		if tool.Name() == key {
			resolved = tool
			break
		}
	}
	if resolved == nil {
		t.Fatalf("worker toolset did not receive %s", key)
	}
	t.Logf("worker toolset received %s", key)

	dec := resolved.CheckPermissions(context.Background(), json.RawMessage(`{}`), permission.Context{Mode: permission.ModeDefault})
	t.Logf("agent-installed command tool permission: %s", dec.Behavior)
	if dec.Behavior == permission.Allow {
		if _, err := resolved.Call(context.Background(), json.RawMessage(`{}`), nil); err != nil {
			t.Fatalf("call custom tool: %v", err)
		}
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Errorf("F-008 GAP: agent-installed command tool executed without approval")
		} else {
			t.Errorf("F-008 GAP: command tool was Allowed but did not execute: %v", statErr)
		}
	} else {
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Errorf("F-008 GAP: command executed despite a %s decision", dec.Behavior)
		}
		t.Logf("blocked at the approval boundary: %s", dec.Behavior)
	}

	// Positive control: the operator-facing executor path still runs the same spec.
	opMarker := filepath.Join(t.TempDir(), "f008-operator-executed")
	opSpec, _ := json.Marshal(map[string]any{
		"command": "printf ARTEX-F008 > " + shellQuote(opMarker),
	})
	if _, err := s.runCommandTool(context.Background(), opSpec, nil, nil); err != nil {
		t.Fatalf("operator executor: %v", err)
	}
	if _, err := os.Stat(opMarker); err != nil {
		t.Errorf("positive control: operator executor did not run the spec: %v", err)
	}
	t.Logf("positive control: operator executor ran the same command spec")

	// Bash itself must keep asking; this is the gate the custom tool bypassed.
	bashDecision := actool.NewBash().CheckPermissions(context.Background(), json.RawMessage(`{"command":"printf x"}`), permission.Context{Mode: permission.ModeDefault})
	if bashDecision.Behavior != permission.Ask {
		t.Errorf("Bash permission = %s, want ask", bashDecision.Behavior)
	}
	t.Logf("Bash permission control: %s", bashDecision.Behavior)
}
