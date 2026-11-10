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

// F-018 evidence: insert_assets merges the caller into an existing global asset
// row. If that row already carries task A's credentials, does B's scoped
// list_assets now read them? This is the read half of F-017's write path.
func TestF018AssetMergeCredentialRead(t *testing.T) {
	s, fA, _ := trafficEvidenceServer(t)
	findingA, err := s.m.pg.GetFinding(fA.FindingID)
	if err != nil || findingA.TaskID == nil {
		t.Fatalf("load task A: %v %+v", err, findingA)
	}
	taskA := *findingA.TaskID
	taskB, err := s.m.CreateTask("F018 task B", "asset merge read probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	const secret = "F018_A_ASSET_PASSWORD"
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

	tsB := agent.NewToolSet(s.m.pg.Exploration(taskB.ExpID), "worker")
	tsB.SetTaskID(taskBID)
	tsB.SetAssetStore(s.m.Assets(), s.m.Assets().Companies())
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	insertB := scopeTool(t, tsB.WorkerTools(), "insert_assets")
	listB := scopeTool(t, tsB.WorkerTools(), "list_assets")

	before, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetA})
	const ownSecret = "F018_B_ASSET_PASSWORD"
	insertRes, _ := f010Call(t, ctxB, insertB, map[string]any{"assets": []map[string]any{{
		"type": "service", "url": urlB, "page_title": "B-observed",
		"auth": []map[string]any{{"type": "form", "username": "bob", "password": ownSecret}},
	}}})
	afterID, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetA})
	afterDSL, _ := f010Call(t, ctxB, listB, map[string]any{"dsl": "domain=" + host})
	var assetB int64
	if err := s.m.pg.QueryRow(`SELECT id FROM assets WHERE url=$1`, urlB).Scan(&assetB); err != nil {
		t.Fatal(err)
	}
	own, _ := f010Call(t, ctxB, listB, map[string]any{"id": assetB})
	var taskIDs string
	if err := s.m.pg.QueryRow(`SELECT task_ids::text FROM assets WHERE id=$1`, assetA).Scan(&taskIDs); err != nil {
		t.Fatal(err)
	}

	fmt.Printf("F018 pre_has_secret=%v insert=%s after_id_has_secret=%v after_dsl_has_secret=%v own_has_secret=%v task_ids=%v\n",
		strings.Contains(before, secret), strings.TrimSpace(insertRes),
		strings.Contains(afterID, secret), strings.Contains(afterDSL, secret), strings.Contains(own, ownSecret), taskIDs)

	if strings.Contains(before, secret) {
		t.Fatal("B read the asset before association; probe invalid")
	}
	if !strings.Contains(insertRes, `"id":`) {
		t.Fatalf("insert_assets failed: %s", insertRes)
	}
	if strings.Contains(afterID, secret) || strings.Contains(afterDSL, secret) {
		t.Fatalf("B read A's auth after the new-URL scope claim: id=%s dsl=%s", afterID, afterDSL)
	}
	if !strings.Contains(own, ownSecret) {
		t.Fatalf("B lost its own auth to redaction: %s", own)
	}
}
