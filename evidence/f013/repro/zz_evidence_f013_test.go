package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

// F-013 evidence: a finding snapshot is a durable copy of raw traffic, not a
// second access-controlled reader. A task-scoped bind must therefore apply the
// same owner+host boundary as traffic_get. Set ARTEX_F013_EXPECT_LEAK=1 only in
// a pre-fix worktree to record the historical cross-task bind.
func TestF013CrossTaskFindingTrafficBind(t *testing.T) {
	s, fA, _ := trafficEvidenceServer(t)
	findingA, err := s.m.pg.GetFinding(fA.FindingID)
	if err != nil || findingA.TaskID == nil {
		t.Fatalf("load task A: %v %+v", err, findingA)
	}
	taskA := *findingA.TaskID
	taskB, err := s.m.CreateTask("F013 task B", "cross-task finding evidence probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	const secret = "F013_CROSS_TASK_HEADER_SECRET"
	host := fmt.Sprintf("f013-a-%d.example.test", taskBID)
	if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: taskA}); err != nil {
		t.Fatal(err)
	}
	urlA := "http://" + host + "/account"
	if err := s.m.traffic.RecordExternalForTask(taskA, traffic.ExternalExchange{
		Method: "GET", URL: urlA, Status: 200,
		RequestHeaders:  map[string]string{"authorization": "Bearer " + secret},
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    `{"owner":"A","secret":"F013_CROSS_TASK_BODY_SECRET"}`,
	}); err != nil {
		t.Fatal(err)
	}
	var idA string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlA).Scan(&idA); err != nil {
		t.Fatal(err)
	}

	// The fixture's A finding is independent of B's finding. B must not be able
	// to copy A's raw capture into its own finding.
	recB, err := s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID: taskBID, ExplorationID: taskB.ExpID, Worker: "test",
		VulnClass: "SCOPE", Name: "B finding", Severity: "low", Summary: "B finding",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldBinding := s.m.pg.GetBool(settingAgentTrafficBinding, false)
	if err := s.m.pg.SetBool(settingAgentTrafficBinding, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.SetBool(settingAgentTrafficBinding, oldBinding) })

	bind := s.toolBindFindingTraffic()
	inputB := json.RawMessage(fmt.Sprintf(`{"finding_id":"%d","traffic_refs":[{"traffic_id":%q,"role":"proof"}]}`, recB.FindingID, idA))
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	resB, err := bind.Call(ctxB, inputB, nil)
	if err != nil {
		t.Fatal(err)
	}
	expectLeak := os.Getenv("ARTEX_F013_EXPECT_LEAK") == "1"
	if expectLeak {
		list, err := s.m.pg.GetFindingTraffic(context.Background(), recB.FindingID)
		if err != nil || len(list.Bindings) != 1 {
			t.Fatalf("pre-fix bind did not reproduce: result=%q err=%v list=%+v", resB.Flatten(), err, list)
		}
		store := s.evidenceStore()
		var body string
		if err := store.WithBinding(context.Background(), recB.FindingID, list.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
			for _, side := range []string{"request", "response"} {
				f, _, err := store.OpenBody(b.Snapshot, side)
				if err != nil {
					return err
				}
				raw, readErr := io.ReadAll(f)
				f.Close()
				if readErr != nil {
					return readErr
				}
				body += string(raw)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("F013_PREFIX cross_bind=bound raw_head_secret=%v raw_body_has_A=%v\n",
			strings.Contains(list.Bindings[0].Snapshot.ReqHead, secret),
			strings.Contains(body, "F013_CROSS_TASK_BODY_SECRET"))
		if !strings.Contains(list.Bindings[0].Snapshot.ReqHead, secret) || !strings.Contains(body, "F013_CROSS_TASK_BODY_SECRET") {
			t.Fatalf("pre-fix cross-task bind did not expose raw traffic: head=%q body=%q", list.Bindings[0].Snapshot.ReqHead, body)
		}
		return
	}

	if !strings.Contains(resB.Flatten(), "outside this run's task-owned assets") {
		t.Fatalf("cross-task bind was not denied: %q", resB.Flatten())
	}
	if list, err := s.m.pg.GetFindingTraffic(context.Background(), recB.FindingID); err != nil || len(list.Bindings) != 0 {
		t.Fatalf("cross-task bind left a snapshot: %+v %v", list, err)
	}

	// A same-task bind remains usable and still copies the raw evidence.
	ctxA := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskA})
	inputA := json.RawMessage(fmt.Sprintf(`{"finding_id":"%d","traffic_refs":[{"traffic_id":%q,"role":"proof"}]}`, fA.FindingID, idA))
	resA, err := bind.Call(ctxA, inputA, nil)
	if err != nil {
		t.Fatal(err)
	}
	own, err := s.m.pg.GetFindingTraffic(context.Background(), fA.FindingID)
	if err != nil || len(own.Bindings) != 1 {
		t.Fatalf("same-task bind failed: result=%q err=%v list=%+v", resA.Flatten(), err, own)
	}
	fmt.Printf("F013 cross_bind=denied snapshot_count=%d own_bind=bound own_bindings=%d\n",
		len(mustFindingTraffic(t, s, recB.FindingID).Bindings), len(own.Bindings))
}

func mustFindingTraffic(t *testing.T, s *Server, findingID int64) *db.FindingTraffic {
	t.Helper()
	list, err := s.m.pg.GetFindingTraffic(context.Background(), findingID)
	if err != nil {
		t.Fatal(err)
	}
	return list
}
