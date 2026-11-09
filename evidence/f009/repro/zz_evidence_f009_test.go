package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// F-009 evidence probe: a reporter run is task-scoped, but the reporter's
// cross-task query tools and update_finding_report are global sinks. The probe
// creates two tasks, then calls those tools with the reporter's task-A context
// against task B. It also checks the global delete tool, which is Allowed and
// performs an irreversible cross-task deletion.
func TestF009Evidence(t *testing.T) {
	s, fA, _ := trafficEvidenceServer(t)
	pg := s.m.pg

	findingA, err := pg.GetFinding(fA.FindingID)
	if err != nil || findingA.TaskID == nil {
		t.Fatalf("load finding A: %v %+v", err, findingA)
	}
	taskA := *findingA.TaskID

	taskB, err := s.m.CreateTask("F-009 scope B", "F-009 scope B", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(taskBID) })

	findingB, err := s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID: taskBID, ExplorationID: taskB.ExpID, Worker: "test",
		VulnClass: "SCOPE", Name: "task B evidence", Severity: "low",
		Summary: "B-task-secret-evidence",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.SetFindingReportVersionByNodeID(context.Background(), findingB.NodeID, "B-original", nil); err != nil {
		t.Fatal(err)
	}

	reporterCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskA})
	reporterTools, _, reporterCleanup := agent.AugmentTools(reporterCtx, "reporter", nil)
	defer reporterCleanup()
	getDetail := f009Tool(t, reporterTools, "get_task_node_detail")
	updateReport := f009Tool(t, reporterTools, "update_finding_report")

	res, err := getDetail.Call(reporterCtx, json.RawMessage(fmt.Sprintf(`{"task_id":%q,"id":%d}`, taskB.ID, findingB.NodeID)), nil)
	if err != nil {
		t.Fatal(err)
	}
	crossRead := strings.Contains(res.Flatten(), "B-task-secret-evidence")

	res, err = updateReport.Call(reporterCtx, json.RawMessage(fmt.Sprintf(`{"finding_id":%d,"report":"F-009 overwrite"}`, findingB.NodeID)), nil)
	if err != nil {
		t.Fatal(err)
	}
	findingBAfter, err := pg.GetFinding(findingB.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	crossWrite := findingBAfter.Report == "F-009 overwrite"

	res, err = getDetail.Call(reporterCtx, json.RawMessage(fmt.Sprintf(`{"task_id":%q,"id":%d}`, fmt.Sprintf("%d", taskA), fA.NodeID)), nil)
	if err != nil {
		t.Fatal(err)
	}
	ownRead := strings.Contains(res.Flatten(), "bound evidence")
	res, err = updateReport.Call(reporterCtx, json.RawMessage(fmt.Sprintf(`{"finding_id":%d,"report":"F-009 own"}`, fA.NodeID)), nil)
	if err != nil || !strings.Contains(res.Flatten(), "updated") {
		t.Fatalf("own-task report control failed: %s %v", res.Flatten(), err)
	}
	ownWrite := true

	autoCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{})
	autoTools, _, autoCleanup := agent.AugmentTools(autoCtx, "auto", nil)
	defer autoCleanup()
	autoGet := f009Tool(t, autoTools, "get_task_node_detail")
	res, err = autoGet.Call(autoCtx, json.RawMessage(fmt.Sprintf(`{"task_id":%q,"id":%d}`, taskB.ID, findingB.NodeID)), nil)
	if err != nil {
		t.Fatal(err)
	}
	autoRead := strings.Contains(res.Flatten(), "B-task-secret-evidence")

	host := fmt.Sprintf("f009-delete-%d.example.test", taskBID)
	if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: taskBID}); err != nil {
		t.Fatal(err)
	}
	autoDelete := f009Tool(t, autoTools, "delete_assets_by_host")
	deleteInput := json.RawMessage(fmt.Sprintf(`{"host":%q}`, host))
	deleteDecision := autoDelete.CheckPermissions(autoCtx, deleteInput, permission.Context{}).Behavior
	deleteAllowed := deleteDecision == permission.Allow
	if deleteAllowed {
		if _, err := autoDelete.Call(autoCtx, deleteInput, nil); err != nil {
			t.Fatal(err)
		}
	}
	remaining, err := s.m.Assets().QueryByTask(taskBID, "root_domain", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	assetDeleted := len(remaining) == 0

	controlHost := host + "-control"
	if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: controlHost, TaskID: taskBID}); err != nil {
		t.Fatal(err)
	}
	controlCounts, err := s.m.Assets().DeleteByHost(controlHost)
	if err != nil {
		t.Fatal(err)
	}
	var controlTotal int64
	for _, n := range controlCounts {
		controlTotal += n
	}
	operatorDelete := controlTotal > 0
	if _, err := pg.SetFindingReportVersionByNodeID(context.Background(), findingB.NodeID, "operator-report", nil); err != nil {
		t.Fatal(err)
	}
	operatorWriteFinding, err := pg.GetFinding(findingB.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	operatorWrite := operatorWriteFinding.Report == "operator-report"

	fmt.Printf("F-009 reporter_cross_read=%v reporter_cross_write=%v own_read=%v own_write=%v auto_read=%v delete_decision=%s delete_allowed=%v asset_deleted=%v operator_delete=%v operator_write=%v\n",
		crossRead, crossWrite, ownRead, ownWrite, autoRead, deleteDecision, deleteAllowed, assetDeleted, operatorDelete, operatorWrite)

	if !ownRead || !ownWrite || !autoRead || !operatorDelete || !operatorWrite {
		t.Fatalf("F-009 positive controls failed: own_read=%v own_write=%v auto_read=%v operator_delete=%v operator_write=%v", ownRead, ownWrite, autoRead, operatorDelete, operatorWrite)
	}
	if crossRead || crossWrite || deleteAllowed {
		t.Fatalf("F-009 GAP: reporter read another task=%v, overwrote another task=%v, global delete was allowed=%v", crossRead, crossWrite, deleteAllowed)
	}
}

func f009Tool(t *testing.T, tools []actool.CoreTool, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range tools {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("tool %q is not bound", name)
	return nil
}
