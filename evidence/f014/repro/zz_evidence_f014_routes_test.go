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
)

// F-014 evidence: the F-011 owner scope must hold on the adjacent read surfaces,
// not only traffic_search/get. A task token is ingest-only; raw exchange/blob,
// findings export, and tool listing must reject it. Replayed tokens after task
// deletion and foreign-host ingestion must fail.
func TestF014AlternateTrafficAndToolRoutes(t *testing.T) {
	s, fA, _ := trafficEvidenceServer(t)
	if err := s.m.SetTrafficEnabled(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.SetTrafficEnabled(false) })
	findingA, err := s.m.pg.GetFinding(fA.FindingID)
	if err != nil || findingA.TaskID == nil {
		t.Fatalf("load task A: %v", err)
	}
	taskA := *findingA.TaskID

	hostA := fmt.Sprintf("f014-a-%d.example.test", taskA)
	if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: hostA, TaskID: taskA}); err != nil {
		t.Fatal(err)
	}
	const bodySecret = "F014_A_RAW_BODY_SECRET"
	urlA := "http://" + hostA + "/large"
	if err := s.m.traffic.RecordExternalForTask(taskA, traffic.ExternalExchange{
		Method: "GET", URL: urlA, Status: 200,
		ResponseHeaders: map[string]string{"content-type": "text/plain"},
		ResponseBody:    bodySecret + strings.Repeat("A", 300000),
	}); err != nil {
		t.Fatal(err)
	}
	var idA, blobHash string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlA).Scan(&idA); err != nil {
		t.Fatal(err)
	}
	if err := s.m.traffic.DB().QueryRow(`SELECT COALESCE(resp_blob,'') FROM exchange_bodies WHERE id=?`, idA).Scan(&blobHash); err != nil || blobHash == "" {
		t.Fatalf("missing blob hash: %q %v", blobHash, err)
	}

	taskB, err := s.m.CreateTask("F014 task B", "alternate route probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })
	hostB := fmt.Sprintf("f014-b-%d.example.test", taskBID)
	if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: hostB, TaskID: taskBID}); err != nil {
		t.Fatal(err)
	}
	tokenA, err := s.m.pg.EnsureTaskTrafficToken(taskA)
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := s.m.pg.EnsureTaskTrafficToken(taskBID)
	if err != nil {
		t.Fatal(err)
	}
	if tokenA == tokenB {
		t.Fatal("task tokens collide")
	}

	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	operator, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	readStatus := func(path string) int { return call("GET", path, tokenA, "").Code }
	routeStatus := map[string]int{
		"traffic":  readStatus("/api/traffic"),
		"exchange": readStatus("/api/traffic/exchange?id=" + idA),
		"blob":     readStatus("/api/traffic/blob?hash=" + blobHash),
		"tools":    readStatus("/api/tools"),
		"export":   readStatus("/api/exploration/findings/export?format=json&scope=all"),
		"operator": call("GET", "/api/traffic/exchange?id="+idA, operator, "").Code,
		"opBlob":   call("GET", "/api/traffic/blob?hash="+blobHash, operator, "").Code,
	}
	cookieReq := httptest.NewRequest("GET", "/api/traffic", nil)
	cookieReq.AddCookie(&http.Cookie{Name: "artex_token", Value: tokenA})
	cookieW := httptest.NewRecorder()
	s.Handler().ServeHTTP(cookieW, cookieReq)
	malformed := call("GET", "/api/traffic", "astk_"+strings.Repeat("f", 64), "")

	// Foreign-host ingestion must fail; own-host ingestion must carry the real
	// task owner, not the token's claimed name or the URL's host.
	foreign := fmt.Sprintf(`{"exchanges":[{"method":"GET","url":"http://%s/foreign","responseBody":"x"}]}`, hostA)
	wForeign := call("POST", "/api/traffic/ingest", tokenB, foreign)
	ownURL := "http://" + hostB + "/own"
	own := fmt.Sprintf(`{"exchanges":[{"method":"GET","url":%q,"responseBody":"own"}]}`, ownURL)
	wOwn := call("POST", "/api/traffic/ingest", tokenB, own)
	var ownOwner int64
	_ = s.m.traffic.DB().QueryRow(`SELECT task_id FROM exchanges WHERE url=?`, ownURL).Scan(&ownOwner)

	// Task-scoped blob tool: B denied, A allowed.
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	ctxA := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskA})
	toolsB, _, closeB := agent.AugmentTools(ctxB, "worker", nil)
	defer closeB()
	toolsA, _, closeA := agent.AugmentTools(ctxA, "worker", nil)
	defer closeA()
	blobB, _ := f010Call(t, ctxB, scopeTool(t, toolsB, "traffic_blob"), map[string]any{"hash": blobHash})
	blobA, _ := f010Call(t, ctxA, scopeTool(t, toolsA, "traffic_blob"), map[string]any{"hash": blobHash})

	// Replay after deleting B: token must no longer resolve.
	if err := s.m.pg.DeleteTask(taskBID); err != nil {
		t.Fatal(err)
	}
	replay := call("POST", "/api/traffic/ingest", tokenB, own)

	var foreignResp struct{ Ingested, Failed int }
	_ = json.Unmarshal(wForeign.Body.Bytes(), &foreignResp)
	var ownResp struct{ Ingested, Failed int }
	_ = json.Unmarshal(wOwn.Body.Bytes(), &ownResp)
	fmt.Printf("F014 traffic=%d exchange=%d blob=%d tools=%d export=%d cookie=%d malformed=%d operator=%d operator_blob=%d foreign_ingested=%d own_ingested=%d own_owner=%d replay=%d blob_b_denied=%v blob_a_has_secret=%v\n",
		routeStatus["traffic"], routeStatus["exchange"], routeStatus["blob"], routeStatus["tools"], routeStatus["export"], cookieW.Code, malformed.Code,
		routeStatus["operator"], routeStatus["opBlob"], foreignResp.Ingested, ownResp.Ingested, ownOwner, replay.Code,
		strings.Contains(blobB, "outside this run's task-owned assets"), strings.Contains(blobA, bodySecret))
	for name, code := range map[string]int{
		"traffic": routeStatus["traffic"], "exchange": routeStatus["exchange"], "blob": routeStatus["blob"],
		"tools": routeStatus["tools"], "export": routeStatus["export"],
	} {
		if code != 401 {
			t.Fatalf("%s with task token = %d, want 401", name, code)
		}
	}
	if cookieW.Code != 401 || malformed.Code != 401 {
		t.Fatalf("cookie=%d malformed=%d, want 401", cookieW.Code, malformed.Code)
	}
	if routeStatus["operator"] != 200 || routeStatus["opBlob"] != 200 {
		t.Fatalf("operator raw routes = exchange %d blob %d, want 200", routeStatus["operator"], routeStatus["opBlob"])
	}
	if wForeign.Code != 200 || !strings.Contains(wForeign.Body.String(), `"ingested":0`) {
		t.Fatalf("foreign ingest = %d %s", wForeign.Code, wForeign.Body)
	}
	if wOwn.Code != 200 || ownResp.Ingested != 1 || ownOwner != taskBID {
		t.Fatalf("own ingest = %d %s owner=%d", wOwn.Code, wOwn.Body, ownOwner)
	}
	if replay.Code != 401 {
		t.Fatalf("replayed token after task deletion = %d, want 401", replay.Code)
	}
	if !strings.Contains(blobB, "outside this run's task-owned assets") || !strings.Contains(blobA, bodySecret) {
		t.Fatalf("blob tool: B=%q A_has_secret=%v", blobB, strings.Contains(blobA, bodySecret))
	}
}
