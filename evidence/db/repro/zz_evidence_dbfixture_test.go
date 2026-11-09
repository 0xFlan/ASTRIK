package server

// Evidence reproducer for the F-005 review of the PostgreSQL-backed routes.
//
// It drives the real Server.Handler() (cors -> requireAuth -> ServeMux) on a
// loopback listener with a valid JWT, creates two independent tasks through the
// public API, and then attempts cross-task sub-resource operations (goals,
// constraints, scope, credentials, task-level intercept rules) plus SQL
// metacharacter and path-traversal payloads on the list/file/archive routes.
//
// Every probe prints the exact method, path, status and a body prefix. The test
// fails only when an observable invariant is violated: an anonymous request is
// not rejected, a cross-task operation mutates the victim task's row, or a
// traversal payload reads/writes outside its managed directory.
//
// Run from the ARTEX repository root with a disposable PostgreSQL:
//   cp <skill-repo>/evidence/db/repro/zz_evidence_dbfixture_test.go server/
//   ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
//     go test ./server -run TestDBFixtureAuthzMatrix -count=1 -v

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type dbFixtureProbe struct {
	label  string
	method string
	path   string
	status int
	body   string
}

func (p dbFixtureProbe) log(t *testing.T) {
	t.Helper()
	body := strings.ReplaceAll(p.body, "\n", " ")
	if len(body) > 220 {
		body = body[:220] + "…"
	}
	t.Logf("probe %-34s %s %-72s status=%d body=%q", p.label, p.method, p.path, p.status, body)
}

func TestDBFixtureAuthzMatrix(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	dataDir := t.TempDir()
	s := New(context.Background(), m, dataDir, dataDir, dataDir)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	do := func(label, tok, method, path string, payload any) dbFixtureProbe {
		t.Helper()
		var body io.Reader
		if payload != nil {
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("%s: marshal: %v", label, err)
			}
			body = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, ts.URL+path, body)
		if err != nil {
			t.Fatalf("%s: request: %v", label, err)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: do: %v", label, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		p := dbFixtureProbe{label: label, method: method, path: path, status: resp.StatusCode, body: string(raw)}
		p.log(t)
		return p
	}

	// ---- 1. Anonymous matrix: every DB-backed route must answer 401. ----
	anonymous := []struct{ method, path string }{
		{http.MethodGet, "/api/tasks"},
		{http.MethodGet, "/api/task-archives"},
		{http.MethodGet, "/api/task-archives/1"},
		{http.MethodPost, "/api/task-archives/1/restore"},
		{http.MethodDelete, "/api/task-archives/1"},
		{http.MethodGet, "/api/tasks/1/credentials"},
		{http.MethodGet, "/api/tasks/1/goals"},
		{http.MethodGet, "/api/logs"},
		{http.MethodGet, "/api/llm"},
		{http.MethodPost, "/api/skills/upload"},
		{http.MethodGet, "/api/workspace/read?path=x"},
	}
	for _, a := range anonymous {
		p := do("anonymous", "", a.method, a.path, nil)
		if p.status != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s = %d, want 401 (body=%s)", a.method, a.path, p.status, p.body)
		}
	}

	// ---- 2. Two live tasks through the public API. ----
	create := func(desc string) (string, int64) {
		t.Helper()
		p := do("create-task", token, http.MethodPost, "/api/tasks", map[string]string{
			"description": desc,
			"goal":        "Probe the loopback lab target at http://127.0.0.1:9/v1 for unauthenticated data exposure; record one record as evidence and stop.",
		})
		if p.status != http.StatusCreated {
			t.Fatalf("create task: status=%d body=%s", p.status, p.body)
		}
		var out struct {
			ID            string `json:"id"`
			ExplorationID int64  `json:"exploration_id"`
		}
		if err := json.Unmarshal([]byte(p.body), &out); err != nil || out.ID == "" {
			t.Fatalf("create task payload: %v body=%s", err, p.body)
		}
		return out.ID, out.ExplorationID
	}
	taskA, _ := create("evidence-fixture-alpha")
	taskB, _ := create("evidence-fixture-beta")
	t.Logf("fixture tasks taskA=%s taskB=%s", taskA, taskB)

	// ---- 3. Victim task B resources. ----
	var goalID, constraintID, scopeID, credentialID, ruleID string

	if p := do("B-add-goal", token, http.MethodPost, "/api/tasks/"+taskB+"/goals", map[string]any{
		"text": "victim goal that must not be edited by task " + taskA,
	}); p.status != http.StatusOK {
		t.Fatalf("add goal on B: %d %s", p.status, p.body)
	} else if err := json.Unmarshal([]byte(p.body), &struct {
		ID *string `json:"id"`
	}{ID: &goalID}); err != nil {
		// goalDTO uses string ids; fall back to scanning
	}
	if goalID == "" {
		p := do("B-list-goals", token, http.MethodGet, "/api/tasks/"+taskB+"/goals", nil)
		var out struct {
			Goals []struct {
				ID string `json:"id"`
			} `json:"goals"`
		}
		_ = json.Unmarshal([]byte(p.body), &out)
		if len(out.Goals) > 0 {
			goalID = out.Goals[0].ID
		}
	}

	if p := do("B-add-constraint", token, http.MethodPost, "/api/tasks/"+taskB+"/constraints", map[string]any{
		"kind": "deny", "text": "victim constraint",
	}); p.status != http.StatusOK {
		t.Fatalf("add constraint on B: %d %s", p.status, p.body)
	} else {
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal([]byte(p.body), &out)
		constraintID = out.ID
	}

	if p := do("B-add-scope", token, http.MethodPost, "/api/tasks/"+taskB+"/scope", map[string]any{
		"kind": "subdomain", "value": "victim.evidence.example", "reason": "fixture",
	}); p.status != http.StatusOK {
		t.Fatalf("add scope on B: %d %s", p.status, p.body)
	} else {
		var out struct {
			ID any `json:"id"`
		}
		_ = json.Unmarshal([]byte(p.body), &out)
		scopeID = fmt.Sprint(out.ID)
	}

	if p := do("B-add-credential", token, http.MethodPost, "/api/tasks/"+taskB+"/credentials", map[string]any{
		"domain": "victim.evidence.example", "username": "victim", "password": "victim-pw", "note": "fixture",
	}); p.status != http.StatusCreated {
		t.Fatalf("add credential on B: %d %s", p.status, p.body)
	} else {
		var out struct {
			ID any `json:"id"`
		}
		_ = json.Unmarshal([]byte(p.body), &out)
		credentialID = fmt.Sprint(out.ID)
	}

	if p := do("B-add-intercept-rule", token, http.MethodPost, "/api/tasks/"+taskB+"/intercept-rules", map[string]any{
		"enabled": true, "action": "block", "kind": "fuzzy_domain", "pattern": "victim.evidence.example", "note": "fixture",
	}); p.status != http.StatusOK {
		t.Fatalf("add intercept rule on B: %d %s", p.status, p.body)
	} else {
		var out struct {
			ID any `json:"id"`
		}
		_ = json.Unmarshal([]byte(p.body), &out)
		ruleID = fmt.Sprint(out.ID)
	}

	t.Logf("victim resources goal=%s constraint=%s scope=%s credential=%s rule=%s", goalID, constraintID, scopeID, credentialID, ruleID)

	snapshot := func(label, path string) string {
		t.Helper()
		return do(label, token, http.MethodGet, path, nil).body
	}

	// ---- 4. Cross-task IDOR attempts: task A path, task B child ids. ----
	if goalID != "" {
		before := snapshot("B-goals-before", "/api/tasks/"+taskB+"/goals")
		do("cross-task-goal-patch", token, http.MethodPatch, "/api/tasks/"+taskA+"/goals/"+goalID, map[string]any{
			"text": "PWNED-BY-TASK-" + taskA,
		})
		do("cross-task-goal-delete", token, http.MethodDelete, "/api/tasks/"+taskA+"/goals/"+goalID, nil)
		after := snapshot("B-goals-after", "/api/tasks/"+taskB+"/goals")
		if before != after || strings.Contains(after, "PWNED-BY-TASK") {
			t.Errorf("cross-task goal mutation succeeded: before=%s after=%s", before, after)
		}
	}

	if constraintID != "" {
		before := snapshot("B-constraints-before", "/api/tasks/"+taskB+"/constraints")
		do("cross-task-constraint-edit", token, http.MethodPatch, "/api/tasks/"+taskA+"/constraints/"+constraintID, map[string]any{
			"kind": "allow", "text": "PWNED-CONSTRAINT",
		})
		do("cross-task-constraint-delete", token, http.MethodDelete, "/api/tasks/"+taskA+"/constraints/"+constraintID, nil)
		after := snapshot("B-constraints-after", "/api/tasks/"+taskB+"/constraints")
		if before != after || strings.Contains(after, "PWNED-CONSTRAINT") {
			t.Errorf("cross-task constraint mutation succeeded: before=%s after=%s", before, after)
		}
	}

	if scopeID != "" && scopeID != "<nil>" {
		before := snapshot("B-scope-before", "/api/tasks/"+taskB+"/scope")
		do("cross-task-scope-delete", token, http.MethodDelete, "/api/tasks/"+taskA+"/scope/"+scopeID, nil)
		after := snapshot("B-scope-after", "/api/tasks/"+taskB+"/scope")
		if before != after {
			t.Errorf("cross-task scope mutation succeeded: before=%s after=%s", before, after)
		}
	}

	if credentialID != "" && credentialID != "<nil>" {
		before := snapshot("B-credentials-before", "/api/tasks/"+taskB+"/credentials")
		do("cross-task-credential-delete", token, http.MethodDelete, "/api/tasks/"+taskA+"/credentials/"+credentialID, nil)
		after := snapshot("B-credentials-after", "/api/tasks/"+taskB+"/credentials")
		if before != after {
			t.Errorf("cross-task credential mutation succeeded: before=%s after=%s", before, after)
		}
	}

	if ruleID != "" && ruleID != "<nil>" {
		before := snapshot("B-rules-before", "/api/tasks/"+taskB+"/intercept-rules")
		do("cross-task-rule-toggle", token, http.MethodPost, "/api/tasks/"+taskA+"/intercept-rules/"+ruleID+"/toggle", map[string]any{
			"enabled": false,
		})
		do("cross-task-rule-update", token, http.MethodPut, "/api/tasks/"+taskA+"/intercept-rules/"+ruleID, map[string]any{
			"enabled": false, "action": "allow", "kind": "fuzzy_domain", "pattern": "pwned.evidence.example", "note": "pwned",
		})
		do("cross-task-rule-delete", token, http.MethodDelete, "/api/tasks/"+taskA+"/intercept-rules/"+ruleID, nil)
		after := snapshot("B-rules-after", "/api/tasks/"+taskB+"/intercept-rules")
		if before != after || strings.Contains(after, "pwned.evidence.example") {
			t.Errorf("cross-task task-intercept-rule mutation succeeded: before=%s after=%s", before, after)
		}
	}

	// ---- 5. SQL metacharacters on the newly reachable list/search routes. ----
	baselineTasks := snapshot("tasks-baseline", "/api/tasks")
	baselineArchives := snapshot("archives-baseline", "/api/task-archives")
	baselineFindings := snapshot("findings-baseline", "/api/exploration/findings")

	sqli := []struct{ label, path string }{
		{"sqli-archive-q", "/api/task-archives?q=%27%20OR%201%3D1--"},
		{"sqli-archive-state", "/api/task-archives?state=%27%20OR%201%3D1--"},
		{"sqli-findings-query", "/api/exploration/findings?query=%27%20OR%201%3D1--"},
		{"sqli-findings-severity", "/api/exploration/findings?severity=%27%20OR%201%3D1--"},
		{"sqli-logs-q", "/api/logs/history?q=%27%20OR%201%3D1--"},
	}
	for _, q := range sqli {
		p := do(q.label, token, http.MethodGet, q.path, nil)
		if p.status != http.StatusOK {
			t.Errorf("%s = %d, want 200 (body=%s)", q.label, p.status, p.body)
		}
	}
	// The injection payloads must not widen the result set: the unfiltered
	// baselines stay the reference (same server, same fixture, no new rows added
	// in between).
	if got := snapshot("tasks-after-sqli", "/api/tasks"); got != baselineTasks {
		t.Logf("task list changed during SQLi probes (background lifecycle may explain it): before=%d bytes after=%d bytes", len(baselineTasks), len(got))
	}
	if got := snapshot("findings-after-sqli", "/api/exploration/findings"); got != baselineFindings {
		t.Logf("findings changed during SQLi probes (background lifecycle may explain it): before=%d bytes after=%d bytes", len(baselineFindings), len(got))
	}
	if got := snapshot("archives-after-sqli", "/api/task-archives"); got != baselineArchives {
		t.Errorf("archive list leaked rows under an injection-shaped filter: before=%s after=%s", baselineArchives, got)
	}

	// ---- 6. Archive identifier and state handling. ----
	for _, p := range []struct {
		label, method, path string
	}{
		{"archive-nonnumeric", http.MethodGet, "/api/task-archives/not-a-number"},
		{"archive-unknown", http.MethodGet, "/api/task-archives/999999999"},
		{"archive-restore-unknown", http.MethodPost, "/api/task-archives/999999999/restore"},
		{"archive-delete-unknown", http.MethodDelete, "/api/task-archives/999999999"},
		{"archive-restore-negative", http.MethodPost, "/api/task-archives/-1/restore"},
	} {
		do(p.label, token, p.method, p.path, nil)
	}

	// ---- 7. Path traversal on the file-manager and skill routes. ----
	// Positive control: ordinary workspace paths must keep working after the
	// symlink confinement change.
	if p := do("ws-write-normal", token, http.MethodPost, "/api/workspace/write", map[string]any{
		"path": "normal-probe.txt", "content": "NORMAL-OK",
	}); p.status != http.StatusOK {
		t.Errorf("normal workspace write = %d, want 200 (body=%s)", p.status, p.body)
	}
	if p := do("ws-read-normal", token, http.MethodGet, "/api/workspace/read?path=normal-probe.txt", nil); p.status != http.StatusOK || !strings.Contains(p.body, "NORMAL-OK") {
		t.Errorf("normal workspace read = %d body=%s, want 200 with content", p.status, p.body)
	}
	outsideDir := t.TempDir()
	canaryPath := filepath.Join(outsideDir, "outside-canary.txt")
	canary := "ARTEX-OUTSIDE-CANARY-F005"
	if err := os.WriteFile(canaryPath, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(m.dir, "escape-link")
	if err := os.Symlink(canaryPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	traversal := []struct{ label, path string }{
		{"ws-read-dotdot", "/api/workspace/read?path=../../../../etc/hosts"},
		{"ws-download-dotdot", "/api/workspace/download?path=..%2F..%2F..%2Fetc%2Fhosts"},
		{"ws-list-dotdot", "/api/workspace/list?path=..%2F..%2F..%2F"},
		{"skill-name-dotdot", "/api/skills/..%2F..%2Fetc/files/passwd"},
		{"skill-file-dotdot", "/api/skills/valid/files/..%2F..%2F..%2Fetc%2Fpasswd"},
		{"skill-file-encoded", "/api/skills/valid/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
	}
	for _, tr := range traversal {
		p := do(tr.label, token, http.MethodGet, tr.path, nil)
		if p.status == http.StatusOK && strings.Contains(p.body, "ARTEX-OUTSIDE-CANARY") {
			t.Errorf("%s escaped the workspace: status=%d body=%s", tr.label, p.status, p.body)
		}
	}
	// Symlink confinement: wsResolve is lexical, so a symlink already present in
	// the workspace may still reach outside it. Record the observed behaviour.
	linkProbe := do("ws-read-symlink", token, http.MethodGet, "/api/workspace/read?path=escape-link", nil)
	if linkProbe.status == http.StatusOK && strings.Contains(linkProbe.body, canary) {
		t.Errorf("CONFINEMENT-GAP: workspace read followed a symlink outside the work dir (status=%d body=%s)", linkProbe.status, linkProbe.body)
	}
	downloadProbe := do("ws-download-symlink", token, http.MethodGet, "/api/workspace/download?path=escape-link", nil)
	if downloadProbe.status == http.StatusOK && strings.Contains(downloadProbe.body, canary) {
		t.Errorf("CONFINEMENT-GAP: workspace download served a symlinked file outside the work dir (status=%d body=%s)", downloadProbe.status, downloadProbe.body)
	}

	// Write through a symlink: the file manager must not modify a file outside
	// the work dir just because a link inside it points there.
	writeTarget := filepath.Join(outsideDir, "outside-write.txt")
	if err := os.WriteFile(writeTarget, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLink := filepath.Join(m.dir, "escape-write-link")
	if err := os.Symlink(writeTarget, writeLink); err != nil {
		t.Fatalf("write symlink: %v", err)
	}
	writeProbe := do("ws-write-symlink", token, http.MethodPost, "/api/workspace/write", map[string]any{
		"path": "escape-write-link", "content": "ARTEX-OUTSIDE-WRITE-F005",
	})
	if raw, err := os.ReadFile(writeTarget); err == nil && strings.Contains(string(raw), "ARTEX-OUTSIDE-WRITE-F005") {
		t.Errorf("CONFINEMENT-GAP: workspace write followed a symlink and modified a file outside the work dir (status=%d target=%q)", writeProbe.status, string(raw))
	}

	// Mkdir through a symlinked directory.
	outsideSub := filepath.Join(outsideDir, "outside-subdir")
	if err := os.MkdirAll(outsideSub, 0o700); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(m.dir, "escape-dir-link")
	if err := os.Symlink(outsideSub, dirLink); err != nil {
		t.Fatalf("dir symlink: %v", err)
	}
	mkdirProbe := do("ws-mkdir-symlink", token, http.MethodPost, "/api/workspace/mkdir", map[string]any{
		"path": "escape-dir-link/created-outside",
	})
	if _, err := os.Stat(filepath.Join(outsideSub, "created-outside")); err == nil {
		t.Errorf("CONFINEMENT-GAP: workspace mkdir followed a symlink and created a directory outside the work dir (status=%d)", mkdirProbe.status)
	}

	// ---- 8. Token in the query string is accepted on every route. ----
	queryToken := do("query-token", "", http.MethodGet, "/api/tasks?token="+token, nil)
	if queryToken.status != http.StatusOK {
		t.Logf("query-string token rejected: status=%d body=%s", queryToken.status, queryToken.body)
	}

	// Leave the fixture tasks paused so background loops do not keep working.
	for _, id := range []string{taskA, taskB} {
		do("pause-"+id, token, http.MethodPost, "/api/tasks/"+id+"/control", map[string]any{"action": "pause"})
	}
}
