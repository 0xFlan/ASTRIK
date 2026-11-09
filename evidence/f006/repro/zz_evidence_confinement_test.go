package server

// Evidence reproducer for F-006: path confinement across every file route.
//
// It drives the real Server.Handler() (cors -> requireAuth -> ServeMux) on a
// loopback listener with a valid JWT and exercises the skill file routes, the
// skill meta/delete routes, chat attachment uploads, the workspace manager, and
// the archive-restore helper with symlinks planted inside each allowed root.
//
// A symlink that points outside the root must not produce a 200 with outside
// content, must not modify an outside file, must not create or delete an outside
// entry, and must not cause an outside upload. In-root I/O must keep working.
//
// Run from the ARTEX repository root with the disposable PostgreSQL:
//   ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
//     go test ./server -run TestFileRouteConfinementMatrix -count=1 -v

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type confinementProbe struct {
	label  string
	method string
	path   string
	status int
	body   string
}

func (p confinementProbe) log(t *testing.T) {
	t.Helper()
	body := strings.ReplaceAll(p.body, "\n", " ")
	if len(body) > 200 {
		body = body[:200] + "…"
	}
	t.Logf("probe %-32s %s %-64s status=%d body=%q", p.label, p.method, p.path, p.status, body)
}

func TestFileRouteConfinementMatrix(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	dataDir := t.TempDir() // skillDir == dataDir, as in the shipped wiring
	s := New(context.Background(), m, dataDir, dataDir, dataDir)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	do := func(label, method, path string, payload any) confinementProbe {
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
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: do: %v", label, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		p := confinementProbe{label: label, method: method, path: path, status: resp.StatusCode, body: string(raw)}
		p.log(t)
		return p
	}

	upload := func(label, path, filename, content string) confinementProbe {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		part, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("%s: form: %v", label, err)
		}
		if _, err := part.Write([]byte(content)); err != nil {
			t.Fatalf("%s: write: %v", label, err)
		}
		if err := mw.Close(); err != nil {
			t.Fatalf("%s: close: %v", label, err)
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL+path, &buf)
		if err != nil {
			t.Fatalf("%s: request: %v", label, err)
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: do: %v", label, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		p := confinementProbe{label: label, method: http.MethodPost, path: path, status: resp.StatusCode, body: string(raw)}
		p.log(t)
		return p
	}

	// ---- 1. Positive controls: ordinary in-root skill I/O must work. ----
	if p := do("skill-create", http.MethodPost, "/api/skills", map[string]any{
		"name": "conf-probe", "description": "path confinement probe", "instructions": "probe body",
	}); p.status != http.StatusCreated {
		t.Fatalf("create skill: status=%d body=%s", p.status, p.body)
	}
	if p := do("skill-write-normal", http.MethodPut, "/api/skills/conf-probe/files/notes/readme.txt", map[string]any{
		"content": "ARTEX-LEGIT-F006",
	}); p.status != http.StatusOK {
		t.Errorf("normal skill write = %d, want 200 (body=%s)", p.status, p.body)
	}
	if p := do("skill-read-normal", http.MethodGet, "/api/skills/conf-probe/files/notes/readme.txt", nil); p.status != http.StatusOK || !strings.Contains(p.body, "ARTEX-LEGIT-F006") {
		t.Errorf("normal skill read = %d body=%s, want 200 with content", p.status, p.body)
	}
	if p := do("skill-mkdir-normal", http.MethodPost, "/api/skills/conf-probe/dirs", map[string]any{"path": "docs"}); p.status != http.StatusCreated {
		t.Errorf("normal skill mkdir = %d, want 201 (body=%s)", p.status, p.body)
	}
	if p := do("skill-delete-normal", http.MethodDelete, "/api/skills/conf-probe/files/notes/readme.txt", nil); p.status != http.StatusOK {
		t.Errorf("normal skill delete = %d, want 200 (body=%s)", p.status, p.body)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "conf-probe", "notes", "readme.txt")); !os.IsNotExist(err) {
		t.Errorf("normal skill delete left the file in place: %v", err)
	}

	// ---- 2. Plant escaping links inside the skill root. ----
	outside := t.TempDir()
	canaryPath := filepath.Join(outside, "canary.txt")
	canary := "ARTEX-OUTSIDE-CANARY-F006"
	if err := os.WriteFile(canaryPath, []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideDir := filepath.Join(outside, "dir")
	if err := os.MkdirAll(outsideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victimPath := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(victimPath, []byte("ARTEX-OUTSIDE-VICTIM-F006"), 0o600); err != nil {
		t.Fatal(err)
	}
	skillRoot := filepath.Join(dataDir, "conf-probe")
	if err := os.Symlink(canaryPath, filepath.Join(skillRoot, "leak")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(skillRoot, "outdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(skillRoot, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canaryPath, filepath.Join(skillRoot, "nested", "escape")); err != nil {
		t.Fatal(err)
	}

	// ---- 3. Skill read/write/mkdir/delete through escaping links. ----
	if p := do("skill-read-filelink", http.MethodGet, "/api/skills/conf-probe/files/leak", nil); p.status == http.StatusOK && strings.Contains(p.body, canary) {
		t.Errorf("F-006 GAP: skill read followed a file symlink outside the skill root (status=%d body=%s)", p.status, p.body)
	}
	if p := do("skill-write-filelink", http.MethodPut, "/api/skills/conf-probe/files/leak", map[string]any{
		"content": "ARTEX-OUTSIDE-WRITE-F006",
	}); p.status == http.StatusOK {
		if raw, err := os.ReadFile(canaryPath); err == nil && strings.Contains(string(raw), "ARTEX-OUTSIDE-WRITE-F006") {
			t.Errorf("F-006 GAP: skill write followed a file symlink and modified an outside file (status=%d)", p.status)
		}
	}
	if p := do("skill-read-dirlink", http.MethodGet, "/api/skills/conf-probe/files/outdir/victim.txt", nil); p.status == http.StatusOK && strings.Contains(p.body, "ARTEX-OUTSIDE-VICTIM-F006") {
		t.Errorf("F-006 GAP: skill read traversed a directory symlink outside the skill root (status=%d body=%s)", p.status, p.body)
	}
	if p := do("skill-mkdir-dirlink", http.MethodPost, "/api/skills/conf-probe/dirs", map[string]any{
		"path": "outdir/created-by-f006",
	}); p.status == http.StatusCreated {
		if _, err := os.Stat(filepath.Join(outsideDir, "created-by-f006")); err == nil {
			t.Errorf("F-006 GAP: skill mkdir followed a directory symlink and created an outside directory (status=%d)", p.status)
		}
	}
	if p := do("skill-delete-dirlink", http.MethodDelete, "/api/skills/conf-probe/files/outdir/victim.txt", nil); p.status == http.StatusOK {
		if _, err := os.Stat(victimPath); os.IsNotExist(err) {
			t.Errorf("F-006 GAP: skill delete followed a directory symlink and deleted an outside file (status=%d)", p.status)
		}
	}
	if p := do("skill-read-nested", http.MethodGet, "/api/skills/conf-probe/files/nested/escape", nil); p.status == http.StatusOK && strings.Contains(p.body, canary) {
		t.Errorf("F-006 GAP: nested skill symlink escaped the skill root (status=%d body=%s)", p.status, p.body)
	}

	// ---- 4. Traversal / absolute / Windows-separator negatives. ----
	for _, q := range []struct{ label, path string }{
		{"skill-dotdot", "/api/skills/conf-probe/files/..%2F..%2F..%2Fetc%2Fpasswd"},
		{"skill-encoded-dotdot", "/api/skills/conf-probe/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
		{"skill-absolute", "/api/skills/conf-probe/files/%2Fetc%2Fpasswd"},
		{"skill-backslash", "/api/skills/conf-probe/files/..%5C..%5Cetc%5Cpasswd"},
	} {
		if p := do(q.label, http.MethodGet, q.path, nil); p.status == http.StatusOK {
			t.Errorf("%s = 200, want non-200 (body=%s)", q.label, p.body)
		}
	}

	// ---- 5. SKILL.md meta rewrite through a symlink. ----
	if p := do("meta-skill-create", http.MethodPost, "/api/skills", map[string]any{
		"name": "conf-meta", "description": "meta confinement probe",
	}); p.status != http.StatusCreated {
		t.Fatalf("create meta skill: status=%d body=%s", p.status, p.body)
	}
	outsideMeta := filepath.Join(outside, "outside-SKILL.md")
	metaBody := "---\nname: conf-meta\ndescription: outside file\ndescription: outside file\n---\nbody\n"
	if err := os.WriteFile(outsideMeta, []byte(metaBody), 0o600); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(dataDir, "conf-meta", "SKILL.md")
	if err := os.Remove(metaPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideMeta, metaPath); err != nil {
		t.Fatal(err)
	}
	if p := do("skill-meta-symlink", http.MethodPut, "/api/skills/conf-meta/meta", map[string]any{
		"description": "ARTEX-OUTSIDE-META-F006",
	}); p.status == http.StatusOK {
		if raw, err := os.ReadFile(outsideMeta); err == nil && strings.Contains(string(raw), "ARTEX-OUTSIDE-META-F006") {
			t.Errorf("F-006 GAP: skill meta update followed SKILL.md symlink and rewrote an outside file (status=%d)", p.status)
		}
	}
	// Deleting the skill removes the link itself, never the outside target.
	if p := do("skill-delete-symlinked-dir", http.MethodDelete, "/api/skills/conf-meta", nil); p.status != http.StatusOK {
		t.Logf("delete symlinked skill: status=%d body=%s", p.status, p.body)
	}
	if _, err := os.Stat(outsideMeta); err != nil {
		t.Errorf("deleting a symlinked skill removed its outside target: %v", err)
	}

	// ---- 6. Chat attachment upload into a symlinked uploads dir. ----
	outsideUploads := filepath.Join(outside, "outside-uploads")
	if err := os.MkdirAll(outsideUploads, 0o700); err != nil {
		t.Fatal(err)
	}
	stagingDir := filepath.Join(m.dir, "drafts", "probe")
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideUploads, filepath.Join(stagingDir, "uploads")); err != nil {
		t.Fatal(err)
	}
	if p := upload("chat-upload-symlink", "/api/chat/upload?scope=staging&id=probe", "escape.txt", "ARTEX-OUTSIDE-UPLOAD-F006"); p.status == http.StatusOK {
		if _, err := os.Stat(filepath.Join(outsideUploads, "escape.txt")); err == nil {
			t.Errorf("F-006 GAP: chat upload followed a symlinked uploads dir and wrote outside the work dir (status=%d body=%s)", p.status, p.body)
		}
	}
	if p := upload("chat-upload-normal", "/api/chat/upload?scope=staging&id=legit", "legit.txt", "ARTEX-LEGIT-UPLOAD-F006"); p.status != http.StatusOK {
		t.Errorf("normal chat upload = %d, want 200 (body=%s)", p.status, p.body)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "drafts", "legit", "uploads", "legit.txt")); err != nil {
		t.Errorf("normal chat upload did not land inside the work dir: %v", err)
	}

	// ---- 7. Workspace manager: same matrix, currently F-005-hardened. ----
	if p := do("ws-write-normal", http.MethodPost, "/api/workspace/write", map[string]any{
		"path": "normal-f006.txt", "content": "ARTEX-WS-LEGIT-F006",
	}); p.status != http.StatusOK {
		t.Errorf("normal workspace write = %d, want 200 (body=%s)", p.status, p.body)
	}
	if p := do("ws-read-normal", http.MethodGet, "/api/workspace/read?path=normal-f006.txt", nil); p.status != http.StatusOK || !strings.Contains(p.body, "ARTEX-WS-LEGIT-F006") {
		t.Errorf("normal workspace read = %d body=%s, want 200 with content", p.status, p.body)
	}
	if err := os.Symlink(canaryPath, filepath.Join(m.dir, "ws-leak")); err != nil {
		t.Fatal(err)
	}
	wsVictim := filepath.Join(outsideDir, "ws-victim.txt")
	if err := os.WriteFile(wsVictim, []byte("ARTEX-WS-VICTIM-F006"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(m.dir, "ws-outdir")); err != nil {
		t.Fatal(err)
	}
	if p := do("ws-read-symlink", http.MethodGet, "/api/workspace/read?path=ws-leak", nil); p.status == http.StatusOK && strings.Contains(p.body, canary) {
		t.Errorf("workspace read escaped through a symlink (status=%d body=%s)", p.status, p.body)
	}
	if p := do("ws-download-symlink", http.MethodGet, "/api/workspace/download?path=ws-leak", nil); p.status == http.StatusOK && strings.Contains(p.body, canary) {
		t.Errorf("workspace download escaped through a symlink (status=%d body=%s)", p.status, p.body)
	}
	if p := do("ws-list-symlink", http.MethodGet, "/api/workspace/list?path=ws-outdir", nil); p.status == http.StatusOK {
		t.Errorf("workspace list traversed a symlinked directory (status=%d body=%s)", p.status, p.body)
	}
	if p := do("ws-delete-symlink", http.MethodDelete, "/api/workspace/delete?path=ws-outdir%2Fws-victim.txt", nil); p.status == http.StatusOK {
		if _, err := os.Stat(wsVictim); os.IsNotExist(err) {
			t.Errorf("workspace delete followed a symlink and removed an outside file (status=%d)", p.status)
		}
	}
	if p := upload("ws-upload-symlink", "/api/workspace/upload?path=ws-outdir", "ws-escape.txt", "ARTEX-WS-OUTSIDE-UPLOAD-F006"); p.status == http.StatusOK {
		if _, err := os.Stat(filepath.Join(outsideDir, "ws-escape.txt")); err == nil {
			t.Errorf("workspace upload followed a symlinked directory and wrote outside (status=%d body=%s)", p.status, p.body)
		}
	}
	if p := do("ws-backslash", http.MethodGet, "/api/workspace/read?path=..%5C..%5Cetc%5Chosts", nil); p.status == http.StatusOK {
		t.Errorf("workspace backslash traversal = 200, want non-200 (body=%s)", p.body)
	}

	// ---- 8. Archive restore helper: symlinked tasks parent must not receive files. ----
	restoreData := t.TempDir()
	outsideTasks := t.TempDir()
	if err := os.Symlink(outsideTasks, filepath.Join(restoreData, "tasks")); err != nil {
		t.Fatal(err)
	}
	extracted := t.TempDir()
	payload := filepath.Join(extracted, "files", "tasks", "42", "artifact.txt")
	if err := os.MkdirAll(filepath.Dir(payload), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("ARTEX-OUTSIDE-RESTORE-F006"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, restoreErr := installTaskArchiveFiles(restoreData, extracted, "42", 1)
	escaped := false
	if _, err := os.Stat(filepath.Join(outsideTasks, "42", "artifact.txt")); err == nil {
		escaped = true
	}
	if stage != nil {
		_ = stage.rollback()
	}
	if escaped {
		t.Errorf("F-006 GAP: archive restore put task files through a symlinked tasks parent, outside the data dir (err=%v)", restoreErr)
	}

	// ---- 9. Token in the query string still authenticates (unchanged). ----
	if p := do("query-token", http.MethodGet, "/api/tasks?token="+token, nil); p.status != http.StatusOK {
		t.Logf("query-string token rejected: status=%d body=%s", p.status, p.body)
	}
}
