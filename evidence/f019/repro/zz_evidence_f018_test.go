package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// F-018/F-019 evidence: inserting a different URL on another task's host must
// not manufacture scope over that host. This is the root-cause regression; the
// scoped-read credential redaction is defense in depth, so the no-metadata
// assertions here must hold even when redaction is disabled.
func TestF018ForeignHostScopeGate(t *testing.T) {
	s, fA, _ := trafficEvidenceServer(t)
	findingA, err := s.m.pg.GetFinding(fA.FindingID)
	if err != nil || findingA.TaskID == nil {
		t.Fatalf("load task A: %v %+v", err, findingA)
	}
	taskA := *findingA.TaskID
	taskB, err := s.m.CreateTask("F018 task B", "scope gate probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	const secret = "F018_A_ASSET_PASSWORD"
	const ownSecret = "F018_B_ASSET_PASSWORD"
	host := fmt.Sprintf("shared-f018-%d.example.test", taskBID)
	urlA := "https://" + host + "/login"
	urlB := "https://" + host + "/other"
	assetA, err := s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL: urlA, TaskID: taskA,
		Auth: []map[string]any{{"type": "form", "username": "alice", "password": secret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const ipA = "203.0.113.10"
	ipURL := "http://" + ipA + "/login"
	assetIPA, err := s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL: ipURL, IP: ipA, TaskID: taskA,
		Auth: []map[string]any{{"type": "form", "username": "ip-alice", "password": secret}},
	})
	if err != nil {
		t.Fatal(err)
	}

	tsB := agent.NewToolSet(s.m.pg.Exploration(taskB.ExpID), "worker")
	tsB.SetTaskID(taskBID)
	tsB.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	insertB := scopeTool(t, tsB.WorkerTools(), "insert_assets")
	listB := scopeTool(t, tsB.WorkerTools(), "list_assets")

	before, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetA})
	insertDenied, _ := f010Call(t, ctxB, insertB, map[string]any{"assets": []map[string]any{{
		"type": "service", "url": urlB, "page_title": "B-observed",
		"auth": []map[string]any{{"type": "form", "username": "bob", "password": ownSecret}},
	}}})
	afterID, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetA})
	afterDSL, _ := f010Call(t, ctxB, listB, map[string]any{"dsl": "domain=" + host})
	var pendingB int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM assets WHERE url=$1`, urlB).Scan(&pendingB); err != nil {
		t.Fatal(err)
	}
	ipInsertDenied, _ := f010Call(t, ctxB, insertB, map[string]any{"assets": []map[string]any{{
		"type": "service", "url": "http://" + ipA + "/foreign",
	}}})
	var pendingIP int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM assets WHERE url=$1`, "http://"+ipA+"/foreign").Scan(&pendingIP); err != nil {
		t.Fatal(err)
	}
	ipRead, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetIPA})
	var taskIDs string
	if err := s.m.pg.QueryRow(`SELECT task_ids::text FROM assets WHERE id=$1`, assetA).Scan(&taskIDs); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("F018 pre_has_secret=%v insert_denied=%q pending_asset=%d after_id_has_url=%v after_id_has_secret=%v after_dsl_has_url=%v after_dsl_has_secret=%v task_ids=%v\n",
		strings.Contains(before, secret), strings.TrimSpace(insertDenied), pendingB,
		strings.Contains(afterID, urlA), strings.Contains(afterID, secret),
		strings.Contains(afterDSL, urlA), strings.Contains(afterDSL, secret), taskIDs)

	if strings.Contains(before, secret) {
		t.Fatal("B read the asset before association; probe invalid")
	}
	if !strings.Contains(strings.ToLower(insertDenied), "outside task scope") {
		t.Fatalf("insert_assets did not reject the unproven host: %s", insertDenied)
	}
	if pendingB != 0 {
		t.Fatalf("rejected insert still created the foreign-host asset: %d", pendingB)
	}
	if taskIDs != fmt.Sprintf("{%d}", taskA) {
		t.Fatalf("foreign insert changed A's ownership: %s", taskIDs)
	}
	if strings.Contains(afterID, urlA) || strings.Contains(afterID, secret) ||
		strings.Contains(afterDSL, urlA) || strings.Contains(afterDSL, secret) {
		t.Fatalf("B read A metadata without scope: id=%s dsl=%s", afterID, afterDSL)
	}
	if !strings.Contains(strings.ToLower(ipInsertDenied), "outside task scope") || pendingIP != 0 || strings.Contains(ipRead, ipURL) || strings.Contains(ipRead, secret) {
		t.Fatalf("IP-literal URL bypassed the scope gate: insert=%s pending=%d read=%s", ipInsertDenied, pendingIP, ipRead)
	}
}

// F-019 shared-scope regression: an explicit grant is the supported claim step.
// It must restore shared metadata discovery without exposing A's credential, and
// B must still be able to insert and read its own asset under that scope.
func TestF018ExplicitScopeDiscovery(t *testing.T) {
	s, fA, _ := trafficEvidenceServer(t)
	findingA, err := s.m.pg.GetFinding(fA.FindingID)
	if err != nil || findingA.TaskID == nil {
		t.Fatalf("load task A: %v %+v", err, findingA)
	}
	taskA := *findingA.TaskID
	taskB, err := s.m.CreateTask("F018 shared task B", "explicit scope probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	const secret = "F018_SHARED_A_PASSWORD"
	const ownSecret = "F018_SHARED_B_PASSWORD"
	host := fmt.Sprintf("shared-f018-grant-%d.example.test", taskBID)
	urlA := "https://" + host + "/login"
	urlB := "https://" + host + "/other"
	assetA, err := s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL: urlA, TaskID: taskA,
		Auth: []map[string]any{{"type": "form", "username": "alice", "password": secret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.Assets().AddAgentScope(taskBID, "subdomain", host, "explicit shared-host grant", "agent"); err != nil {
		t.Fatal(err)
	}

	tsB := agent.NewToolSet(s.m.pg.Exploration(taskB.ExpID), "worker")
	tsB.SetTaskID(taskBID)
	tsB.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	insertB := scopeTool(t, tsB.WorkerTools(), "insert_assets")
	listB := scopeTool(t, tsB.WorkerTools(), "list_assets")

	byID, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetA})
	byDSL, _ := f010Call(t, ctxB, listB, map[string]any{"dsl": "domain=" + host})
	insertRes, _ := f010Call(t, ctxB, insertB, map[string]any{"assets": []map[string]any{{
		"type": "service", "url": urlB, "page_title": "B-observed",
		"auth": []map[string]any{{"type": "form", "username": "bob", "password": ownSecret}},
	}}})
	var assetB int64
	if err := s.m.pg.QueryRow(`SELECT id FROM assets WHERE url=$1`, urlB).Scan(&assetB); err != nil {
		t.Fatalf("own asset under explicit scope: %v (insert=%s)", err, insertRes)
	}
	own, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetB})

	fmt.Printf("F018 grant_id_has_url=%v grant_id_has_secret=%v grant_dsl_has_url=%v grant_dsl_has_secret=%v insert=%q own_has_secret=%v\n",
		strings.Contains(byID, urlA), strings.Contains(byID, secret),
		strings.Contains(byDSL, urlA), strings.Contains(byDSL, secret),
		strings.TrimSpace(insertRes), strings.Contains(own, ownSecret))

	if !strings.Contains(byID, urlA) || !strings.Contains(byDSL, urlA) {
		t.Fatalf("explicit scope did not restore shared discovery: id=%s dsl=%s", byID, byDSL)
	}
	if strings.Contains(byID, secret) || strings.Contains(byDSL, secret) {
		t.Fatalf("explicit scope exposed A's credential: id=%s dsl=%s", byID, byDSL)
	}
	if !strings.Contains(own, ownSecret) {
		t.Fatalf("B lost its own auth: %s", own)
	}
}
