package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func f010Seed(t *testing.T, s *Server, url, auth, response string) string {
	t.Helper()
	if err := s.m.traffic.RecordExternal(traffic.ExternalExchange{
		Method: "GET", URL: url, Status: 200,
		RequestHeaders:  map[string]string{"authorization": auth, "cookie": "session=f010-cookie"},
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    response,
	}); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, url).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func f010Call(t *testing.T, ctx context.Context, tool actool.CoreTool, input any) (string, permission.Behavior) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decision := tool.CheckPermissions(ctx, raw, permission.Context{})
	res, err := tool.Call(ctx, raw, nil)
	if err != nil {
		t.Fatalf("%s call: %v", tool.Name(), err)
	}
	return res.Flatten(), decision.Behavior
}

// F-010 evidence: a worker in task B must not read task A's captured
// Authorization header (or its oversized response blob), and the token must not
// be replayable. Own-task traffic and the operator's raw Traffic.Get stay live.
func TestF010TrafficCrossTaskCredentialReadAndReplay(t *testing.T) {
	s, fA, _ := trafficEvidenceServer(t)
	if err := s.m.SetTrafficEnabled(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.SetTrafficEnabled(false) })

	findingA, err := s.m.pg.GetFinding(fA.FindingID)
	if err != nil || findingA.TaskID == nil {
		t.Fatalf("load task A: %v %+v", err, findingA)
	}
	taskA := *findingA.TaskID
	taskB, err := s.m.CreateTask("F010 task B", "cross-task traffic probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	hostA := fmt.Sprintf("f010-a-%d.example.test", taskA)
	hostB := fmt.Sprintf("f010-b-%d.example.test", taskBID)
	for _, asset := range []struct {
		host string
		task int64
	}{{hostA, taskA}, {hostB, taskBID}} {
		if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: asset.host, TaskID: asset.task}); err != nil {
			t.Fatal(err)
		}
	}

	const tokenA = "F010_TASK_A_SECRET"
	const blobSecret = "F010_BLOB_A_SECRET"
	large := strings.Repeat("A", 300*1024) + blobSecret
	idA := f010Seed(t, s, "http://"+hostA+"/account", "Bearer "+tokenA, `{"account":"A","password":"BODY_A_PASSWORD"}`+"\n"+large)
	idB := f010Seed(t, s, "http://"+hostB+"/account", "Bearer F010_TASK_B_SECRET", `{"account":"B","token":"BODY_B_SECRET"}`)

	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	tools, _, cleanup := agent.AugmentTools(ctxB, "worker", nil)
	defer cleanup()
	search := scopeTool(t, tools, "traffic_search")
	get := scopeTool(t, tools, "traffic_get")
	blob := scopeTool(t, tools, "traffic_blob")

	crossSearch, crossSearchPerm := f010Call(t, ctxB, search, map[string]any{"host": hostA})
	ownSearch, ownSearchPerm := f010Call(t, ctxB, search, map[string]any{"host": hostB})
	crossGet, crossGetPerm := f010Call(t, ctxB, get, map[string]any{"id": idA})
	ownGet, ownGetPerm := f010Call(t, ctxB, get, map[string]any{"id": idB})

	// The oversized A response exposes its blob pointer only in the raw,
	// operator-side packet; task B must not be able to use that hash either.
	operatorReq, operatorResp, err := s.m.traffic.Get(idA)
	if err != nil {
		t.Fatal(err)
	}
	hash := ""
	if i := strings.Index(operatorResp, "@blob sha256:"); i >= 0 {
		hash = strings.Fields(operatorResp[i+len("@blob sha256:"):])[0]
	}
	blobRead := false
	blobPerm := permission.Behavior("")
	if hash != "" {
		var out string
		out, blobPerm = f010Call(t, ctxB, blob, map[string]any{"hash": hash, "offset": 300 * 1024})
		blobRead = strings.Contains(out, blobSecret)
	}

	// Replay control: take the token the task-B tool output exposed and use it
	// against a local service that requires exactly task A's credential.
	replayToken := ""
	if i := strings.Index(crossGet, "Bearer "); i >= 0 {
		replayToken = strings.Fields(crossGet[i+len("Bearer "):])[0]
	}
	replayed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+tokenA {
			replayed = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("replayed"))
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	if replayToken != "" {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.Header.Set("Authorization", "Bearer "+replayToken)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}

	crossVisible := strings.Contains(crossGet, tokenA) || strings.Contains(crossGet, "BODY_A_PASSWORD") || strings.Contains(crossGet, blobSecret)
	ownVisible := strings.Contains(ownGet, `"account":"B"`)
	ownTokenRedacted := !strings.Contains(ownGet, "F010_TASK_B_SECRET") && strings.Contains(ownGet, "[redacted]")
	operatorVisible := strings.Contains(operatorReq, tokenA)

	fmt.Printf("F010 cross_search=%v cross_search_perm=%s cross_get_visible=%v cross_get_perm=%s cross_blob_read=%v cross_blob_perm=%s replay=%v own_search=%v own_search_perm=%s own_read=%v own_read_perm=%s own_token_redacted=%v operator_raw=%v\n",
		strings.Contains(crossSearch, idA), crossSearchPerm,
		crossVisible, crossGetPerm, blobRead, blobPerm, replayed,
		strings.Contains(ownSearch, idB), ownSearchPerm, ownVisible, ownGetPerm, ownTokenRedacted, operatorVisible)

	if strings.Contains(crossSearch, idA) || crossSearchPerm != permission.Deny {
		t.Fatalf("cross-task search not blocked: result=%q perm=%s", crossSearch, crossSearchPerm)
	}
	if crossGetPerm != permission.Deny || crossVisible {
		t.Fatalf("cross-task get not blocked: result=%q perm=%s", crossGet, crossGetPerm)
	}
	if blobRead || (hash != "" && blobPerm != permission.Deny) {
		t.Fatalf("cross-task blob not blocked: read=%v perm=%s hash=%q", blobRead, blobPerm, hash)
	}
	if replayed {
		t.Fatal("captured task-A credential replayed successfully")
	}
	if !strings.Contains(ownSearch, idB) || ownSearchPerm != permission.Allow || !ownVisible || ownGetPerm != permission.Allow {
		t.Fatalf("own-task read broke: search=%q perm=%s get=%q perm=%s", ownSearch, ownSearchPerm, ownGet, ownGetPerm)
	}
	if !ownTokenRedacted {
		t.Fatalf("own-task credential was not redacted: %q", ownGet)
	}
	if !operatorVisible {
		t.Fatal("operator raw traffic inspection broke")
	}
}
