package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

// F-017 evidence: a worker bypasses the model and calls the write tools
// directly. The task's own store must reject foreign finding/evidence anchors,
// while the ingest-only task token must stay unable to authenticate any other
// route. The same fixture measures whether compact traffic IDs and BIGSERIAL
// finding/asset IDs make F-013's known-ID prerequisite practical.
func TestF017DirectBackendAuthorization(t *testing.T) {
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
	taskB, err := s.m.CreateTask("F017 task B", "direct backend authorization probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	hostA := fmt.Sprintf("f017-a-%d.example.test", taskA)
	hostB := fmt.Sprintf("f017-b-%d.example.test", taskBID)
	assetA, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: hostA, TaskID: taskA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: hostB, TaskID: taskBID}); err != nil {
		t.Fatal(err)
	}

	const aSecret = "F017_A_RAW_SECRET"
	urlA := "http://" + hostA + "/a"
	if err := s.m.traffic.RecordExternalForTask(taskA, traffic.ExternalExchange{
		Method: "GET", URL: urlA, Status: 200,
		ResponseHeaders: map[string]string{"content-type": "text/plain"},
		ResponseBody:    aSecret,
	}); err != nil {
		t.Fatal(err)
	}
	var idA string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlA).Scan(&idA); err != nil {
		t.Fatal(err)
	}
	urlB := "http://" + hostB + "/b"
	if err := s.m.traffic.RecordExternalForTask(taskBID, traffic.ExternalExchange{Method: "GET", URL: urlB, Status: 200, ResponseBody: "B"}); err != nil {
		t.Fatal(err)
	}
	var idB string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlB).Scan(&idB); err != nil {
		t.Fatal(err)
	}

	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	tsB := agent.NewToolSet(s.m.pg.Exploration(taskB.ExpID), "worker")
	tsB.SetTaskID(taskBID)
	tsB.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	toolsB := tsB.WorkerTools()
	reportB := scopeTool(t, toolsB, "report_finding")
	factB := scopeTool(t, toolsB, "record_fact")
	insertB := scopeTool(t, toolsB, "insert_assets")
	serverToolsB, _, cleanupB := agent.AugmentTools(ctxB, "worker", nil)
	defer cleanupB()
	getTrafficB := scopeTool(t, serverToolsB, "traffic_get")
	findingTrafficB := scopeTool(t, serverToolsB, "get_finding_traffic")

	// 1. Direct write tool calls with a foreign asset ID.
	reportRes, _ := f010Call(t, ctxB, reportB, map[string]any{
		"vulnclass": "SCOPE", "severity": "low", "summary": "foreign asset anchor",
		"evidence": "direct tool call", "asset_ids": []int64{assetA},
	})
	reportDenied := strings.Contains(strings.ToLower(reportRes), "scope") && strings.Contains(strings.ToLower(reportRes), "asset")
	var anchored int
	_ = s.m.pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND asset_ids @> $2::jsonb`, taskBID, fmt.Sprintf("[%d]", assetA)).Scan(&anchored)

	factRes, _ := f010Call(t, ctxB, factB, map[string]any{
		"summary": "foreign evidence anchor", "detail": "direct tool call", "asset_ids": []int64{assetA},
	})
	factDenied := strings.Contains(strings.ToLower(factRes), "scope") && strings.Contains(strings.ToLower(factRes), "asset")

	// 2. Registering a foreign host through insert_assets expands B's ingest
	// allowlist. Measure the before/after rather than assuming F-011's host check
	// is the whole boundary.
	tokenB, err := s.m.pg.EnsureTaskTrafficToken(taskBID)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	call := func(method, path, token, body string) (int, string) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	foreignBody := fmt.Sprintf(`{"exchanges":[{"method":"GET","url":"http://%s/pre-insert","responseBody":"x"}]}`, hostA)
	preCode, preBody := call("POST", "/api/traffic/ingest", tokenB, foreignBody)

	insertRes, _ := f010Call(t, ctxB, insertB, map[string]any{"assets": []map[string]any{{
		"type": "service", "url": "http://" + hostA + "/claimed-by-b",
	}}})
	hostsAfter, err := s.m.Assets().HostsByTaskWithSources(taskBID)
	if err != nil {
		t.Fatal(err)
	}
	hostExpanded := false
	for _, h := range hostsAfter {
		if strings.EqualFold(h, hostA) {
			hostExpanded = true
		}
	}
	postCode, postBody := call("POST", "/api/traffic/ingest", tokenB, foreignBody)
	ownBody := fmt.Sprintf(`{"exchanges":[{"method":"GET","url":"http://%s/own","responseBody":"own"}]}`, hostB)
	ownCode, ownBodyResp := call("POST", "/api/traffic/ingest", tokenB, ownBody)
	var postOwner int64
	_ = s.m.traffic.DB().QueryRow(`SELECT task_id FROM exchanges WHERE url=?`, "http://"+hostA+"/pre-insert").Scan(&postOwner)

	// 3. Task-token authorization on every adjacent read/write route.
	routeStatus := map[string]int{
		"tasks":        0,
		"tools":        0,
		"finding":      0,
		"finding_traf": 0,
		"exchange":     0,
		"chat":         0,
	}
	routeStatus["tasks"], _ = call("GET", "/api/tasks", tokenB, "")
	routeStatus["tools"], _ = call("GET", "/api/tools", tokenB, "")
	routeStatus["finding"], _ = call("GET", fmt.Sprintf("/api/exploration/findings/%d", fA.FindingID), tokenB, "")
	routeStatus["finding_traf"], _ = call("GET", fmt.Sprintf("/api/exploration/findings/%d/traffic", fA.FindingID), tokenB, "")
	routeStatus["exchange"], _ = call("GET", "/api/traffic/exchange?id="+idA, tokenB, "")
	routeStatus["chat"], _ = call("POST", "/api/chat", tokenB, `{}`)
	malformed, _ := call("GET", "/api/traffic", "astk_"+strings.Repeat("f", 64), "")
	cookieReq, _ := http.NewRequest("GET", ts.URL+"/api/traffic", nil)
	cookieReq.AddCookie(&http.Cookie{Name: "artex_token", Value: tokenB})
	cookieResp, err := http.DefaultClient.Do(cookieReq)
	if err != nil {
		t.Fatal(err)
	}
	cookieResp.Body.Close()
	opCode, opBody := call("GET", "/api/traffic/exchange?id="+idA, operator, "")

	// 4. Predictable IDs: traffic IDs are unix seconds plus a process sequence,
	// finding and asset IDs are BIGSERIAL. A task that knows its own ID can
	// derive the adjacent A row. Test whether any allowed read path accepts it.
	trafficGuess := ""
	if tsPart, seqPart, ok := strings.Cut(idB, "-"); ok {
		if n, err := strconv.Atoi(seqPart); err == nil && n > 0 {
			trafficGuess = fmt.Sprintf("%s-%04d", tsPart, n-1)
		}
	}
	guessDenied := ""
	if trafficGuess != "" && trafficGuess != idB {
		guessDenied, _ = f010Call(t, ctxB, getTrafficB, map[string]any{"id": trafficGuess})
	}

	// Adjacent findings: A2 then B2, so B can derive A2 from its own B2 id.
	taskAObj := s.m.ResolveTask(fmt.Sprintf("%d", taskA))
	if taskAObj == nil {
		t.Fatal("task A disappeared")
	}
	a2, err := s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID: taskA, ExplorationID: taskAObj.ExpID, Worker: "probe",
		VulnClass: "SCOPE", Severity: "low", Summary: "A2 sequential id",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID: taskBID, ExplorationID: taskB.ExpID, Worker: "probe",
		VulnClass: "SCOPE", Severity: "low", Summary: "B2 sequential id",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	findingGuess := b2.FindingID - 1
	findingTrafficDenied, _ := f010Call(t, ctxB, findingTrafficB, map[string]any{"finding_id": findingGuess})
	_ = a2

	// 5. Replay after deleting B, then restore cleanly.
	if err := s.m.pg.DeleteTask(taskBID); err != nil {
		t.Fatal(err)
	}
	replayCode, _ := call("POST", "/api/traffic/ingest", tokenB, ownBody)

	fmt.Printf("F017 report_foreign_asset=%v anchored=%d fact_foreign_asset=%v pre_ingest=%d post_ingest=%d host_expanded=%v post_owner=%d own_ingest=%d/%v routes=%v malformed=%d cookie=%d operator=%d traffic_id_A=%s traffic_id_B=%s traffic_guess=%s traffic_guess_denied=%v finding_A2=%d finding_B2=%d finding_guess=%d finding_guess_denied=%v replay=%d\n",
		reportDenied, anchored, factDenied, preCode, postCode, hostExpanded, postOwner, ownCode, strings.Contains(ownBodyResp, `"ingested":1`),
		routeStatus, malformed, cookieResp.StatusCode, opCode, idA, idB, trafficGuess,
		strings.Contains(guessDenied, "outside") || strings.Contains(guessDenied, "not found") || strings.Contains(guessDenied, "denied"),
		a2.FindingID, b2.FindingID, findingGuess,
		strings.Contains(findingTrafficDenied, "cannot read"), replayCode)

	if !reportDenied || anchored != 0 {
		t.Fatalf("report_finding accepted a foreign asset anchor: %s", reportRes)
	}
	if !factDenied {
		t.Fatalf("record_fact accepted a foreign asset anchor: %s", factRes)
	}
	if preCode != 200 || !strings.Contains(preBody, `"ingested":0`) {
		t.Fatalf("pre-insert foreign ingest = %d %s", preCode, preBody)
	}
	if !hostExpanded || postCode != 200 || !strings.Contains(postBody, `"ingested":1`) || postOwner != taskBID {
		t.Fatalf("insert_assets did not expand ingest scope as measured: expanded=%v code=%d body=%s owner=%d insert=%s", hostExpanded, postCode, postBody, postOwner, insertRes)
	}
	if ownCode != 200 || !strings.Contains(ownBodyResp, `"ingested":1`) {
		t.Fatalf("own ingest = %d %s", ownCode, ownBodyResp)
	}
	for name, code := range routeStatus {
		if code != http.StatusUnauthorized {
			t.Fatalf("%s with task token = %d, want 401", name, code)
		}
	}
	if malformed != http.StatusUnauthorized || cookieResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("malformed=%d cookie=%d, want 401", malformed, cookieResp.StatusCode)
	}
	if opCode != 200 || !strings.Contains(opBody, aSecret) {
		t.Fatalf("operator raw route = %d %s", opCode, opBody)
	}
	if trafficGuess == "" || !strings.Contains(guessDenied, "outside") {
		t.Fatalf("guessed traffic id %q result: %s", trafficGuess, guessDenied)
	}
	if findingGuess <= 0 || !strings.Contains(findingTrafficDenied, "cannot read") {
		t.Fatalf("guessed finding id %d result: %s", findingGuess, findingTrafficDenied)
	}
	if replayCode != http.StatusUnauthorized {
		t.Fatalf("replay after delete = %d, want 401", replayCode)
	}
}
