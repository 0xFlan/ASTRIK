package server

// This probe is intentionally written against the pre-F-011 API. Run it in a
// clean worktree at F-010 commit 0d22b30; it must not compile on the fixed tree
// because RecordExternal has no task argument and traffic.Tools takes HostScope.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/permission"
)

func TestF011PreFixSameHostTrafficRead(t *testing.T) {
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
	taskB, err := s.m.CreateTask("F011 prefix task B", "same-host prefix probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	host := fmt.Sprintf("f011-prefix-%d.example.test", taskBID)
	for _, task := range []int64{taskA, taskBID} {
		if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: task}); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "F011_PREFIX_A_SECRET"
	urlA := "http://" + host + "/account"
	if err := s.m.traffic.RecordExternal(traffic.ExternalExchange{
		Method: "GET", URL: urlA, Status: 200,
		RequestHeaders:  map[string]string{"authorization": "Bearer " + secret},
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    `{"owner":"A"}`,
	}); err != nil {
		t.Fatal(err)
	}
	var idA string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlA).Scan(&idA); err != nil {
		t.Fatal(err)
	}
	urlB := "http://" + host + "/own-b"
	if err := s.m.traffic.RecordExternal(traffic.ExternalExchange{
		Method: "GET", URL: urlB, Status: 200,
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    `{"owner":"B"}`,
	}); err != nil {
		t.Fatal(err)
	}
	var idB string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlB).Scan(&idB); err != nil {
		t.Fatal(err)
	}

	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	tools := s.m.traffic.Tools(s.m.trafficHostScope)
	search := scopeTool(t, tools, "traffic_search")
	get := scopeTool(t, tools, "traffic_get")
	searchRes, searchPerm := f010Call(t, ctxB, search, map[string]any{"host": host, "limit": 10})
	getRes, getPerm := f010Call(t, ctxB, get, map[string]any{"id": idA})
	fmt.Printf("F011_PREFIX same_host_search_has_A=%v own_B=%v search_perm=%s get_A_has_body=%v get_A_has_secret=%v get_perm=%s\n",
		strings.Contains(searchRes, idA), strings.Contains(searchRes, idB), searchPerm,
		strings.Contains(getRes, `"owner":"A"`), strings.Contains(getRes, secret), getPerm)
	if !strings.Contains(searchRes, idA) || !strings.Contains(getRes, `"owner":"A"`) {
		t.Fatalf("pre-fix same-host cross-task metadata/body read did not reproduce: search=%q get=%q", searchRes, getRes)
	}
	if strings.Contains(getRes, secret) {
		t.Fatalf("pre-fix F-010 redaction unexpectedly leaked the credential: %q", getRes)
	}
	if searchPerm != permission.Allow || getPerm != permission.Allow {
		t.Fatalf("pre-fix tools unexpectedly denied the read: search=%s get=%s", searchPerm, getPerm)
	}
}
