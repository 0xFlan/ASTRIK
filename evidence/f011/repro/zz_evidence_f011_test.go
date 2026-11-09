package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/norma/permission"
)

// F-011 evidence: two tasks own the same asset host. Ownership must still
// partition their exchanges, agent-facing redaction must cover query strings,
// custom headers, cookies, form/nested JSON and binary blobs, and a task-scoped
// ingest token must not be able to plant traffic outside that task's assets.
func TestF011SameHostOwnershipRedactionAndIngest(t *testing.T) {
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
	taskB, err := s.m.CreateTask("F011 task B", "same-host ownership probe", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskBID, err := strconv.ParseInt(taskB.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteTask(taskBID) })

	host := fmt.Sprintf("f011-shared-%d.example.test", taskBID)
	for _, task := range []int64{taskA, taskBID} {
		if _, err := s.m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: host, TaskID: task}); err != nil {
			t.Fatal(err)
		}
	}

	const (
		headerSecret = "F011_HEADER_A_SECRET"
		cookieSecret = "F011_COOKIE_A_SECRET"
		querySecret  = "F011_QUERY_A_SECRET"
		customSecret = "F011_CUSTOM_A_SECRET"
		nestedSecret = "F011_NESTED_A_SECRET"
		formSecret   = "F011_FORM_A_SECRET"
		bodySecret   = "F011_BODY_A_SECRET"
		binarySecret = "F011_BINARY_A_SECRET"
	)
	urlA := "http://" + host + "/account?access_token=" + querySecret + "&view=full"
	if err := s.m.traffic.RecordExternalForTask(taskA, traffic.ExternalExchange{
		Method: "POST", URL: urlA, Status: 200,
		RequestHeaders: map[string]string{
			"authorization": "Bearer " + headerSecret,
			"cookie":        "sid=" + cookieSecret,
			"x-session-key": customSecret,
			"content-type":  "application/x-www-form-urlencoded",
		},
		RequestBody: "user=a&secret=" + formSecret,
		ResponseHeaders: map[string]string{
			"content-type": "application/json",
			"set-cookie":   "resp=" + cookieSecret,
		},
		ResponseBody: `{"auth":{"credential":"` + nestedSecret + `"},"token":"` + bodySecret + `","ok":true}`,
	}); err != nil {
		t.Fatal(err)
	}
	var idA string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlA).Scan(&idA); err != nil {
		t.Fatal(err)
	}

	const ownBSecret = "F011_OWN_B_SECRET"
	urlB := "http://" + host + "/own-b?token=" + ownBSecret
	if err := s.m.traffic.RecordExternalForTask(taskBID, traffic.ExternalExchange{
		Method: "GET", URL: urlB, Status: 200,
		RequestHeaders:  map[string]string{"authorization": "Bearer " + ownBSecret},
		ResponseHeaders: map[string]string{"content-type": "application/json"},
		ResponseBody:    `{"owner":"B","ok":true}`,
	}); err != nil {
		t.Fatal(err)
	}
	var idB string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, urlB).Scan(&idB); err != nil {
		t.Fatal(err)
	}

	// A binary oversized body owned by task A: the agent-facing blob reader must
	// not expose a hex rendering of it.
	binURL := "http://" + host + "/binary"
	if err := s.m.traffic.RecordExternalForTask(taskA, traffic.ExternalExchange{
		Method: "GET", URL: binURL, Status: 200,
		ResponseHeaders: map[string]string{"content-type": "application/octet-stream"},
		ResponseBody:    "\x00\x01" + strings.Repeat("X", 300*1024) + binarySecret,
	}); err != nil {
		t.Fatal(err)
	}
	var binID string
	if err := s.m.traffic.DB().QueryRow(`SELECT id FROM exchanges WHERE url=?`, binURL).Scan(&binID); err != nil {
		t.Fatal(err)
	}
	_, rawBin, err := s.m.traffic.Get(binID)
	if err != nil {
		t.Fatal(err)
	}
	hash := ""
	if i := strings.Index(rawBin, "@blob sha256:"); i >= 0 {
		hash = strings.Fields(rawBin[i+len("@blob sha256:"):])[0]
	}
	if hash == "" {
		t.Fatal("binary fixture did not spill to a blob")
	}

	ctxA := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskA})
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskBID})
	toolsA, _, cleanupA := agent.AugmentTools(ctxA, "worker", nil)
	defer cleanupA()
	toolsB, _, cleanupB := agent.AugmentTools(ctxB, "worker", nil)
	defer cleanupB()
	searchA, getA, blobA := scopeTool(t, toolsA, "traffic_search"), scopeTool(t, toolsA, "traffic_get"), scopeTool(t, toolsA, "traffic_blob")
	searchB, getB, blobB := scopeTool(t, toolsB, "traffic_search"), scopeTool(t, toolsB, "traffic_get"), scopeTool(t, toolsB, "traffic_blob")

	crossSearch, crossSearchPerm := f010Call(t, ctxB, searchB, map[string]any{"host": host})
	crossGet, crossGetPerm := f010Call(t, ctxB, getB, map[string]any{"id": idA})
	crossBlob, crossBlobPerm := f010Call(t, ctxB, blobB, map[string]any{"hash": hash})
	ownSearch, ownSearchPerm := f010Call(t, ctxB, searchB, map[string]any{"host": host, "contains": "/own-b"})
	ownGet, ownGetPerm := f010Call(t, ctxB, getB, map[string]any{"id": idB})
	ownASearch, ownASearchPerm := f010Call(t, ctxA, searchA, map[string]any{"host": host, "contains": "/account"})
	ownAGet, ownAGetPerm := f010Call(t, ctxA, getA, map[string]any{"id": idA})
	ownABlob, _ := f010Call(t, ctxA, blobA, map[string]any{"hash": hash, "offset": 300 * 1024})

	// A wrapper is the agent's actual binding surface; it must still delegate
	// CheckPermissions and Call, not just look scoped in the catalog.
	wrapped := agent.DecorateTool(getB, "", nil)
	raw, _ := json.Marshal(map[string]string{"id": idA})
	wrappedDecision := wrapped.CheckPermissions(ctxB, raw, permission.Context{})
	wrappedCall, wrappedCallPerm := f010Call(t, ctxB, wrapped, map[string]any{"id": idA})

	operatorReq, _, err := s.m.traffic.Get(idA)
	if err != nil {
		t.Fatal(err)
	}
	operatorRaw := strings.Contains(operatorReq, headerSecret) && strings.Contains(operatorReq, querySecret)

	// Task-scoped ingest: B may write its own host, but not a foreign host. The
	// row is stamped B and remains invisible to A.
	tokenB, err := s.m.pg.EnsureTaskTrafficToken(taskBID)
	if err != nil {
		t.Fatal(err)
	}
	ingestWith := func(token, url string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"exchanges":[{"method":"GET","url":%q,"status":200,"responseBody":"ingested-marker"}]}`, url)
		r := httptest.NewRequest("POST", "/api/traffic/ingest", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	ownIngest := ingestWith(tokenB, "http://"+host+"/ingested-b")
	foreignIngest := ingestWith(tokenB, "http://f011-foreign.example.test/ingested")
	if ownIngest.Code != 200 || !strings.Contains(ownIngest.Body.String(), `"ingested":1`) || !strings.Contains(ownIngest.Body.String(), `"task_scoped":true`) {
		t.Fatalf("own ingest failed: %d %s", ownIngest.Code, ownIngest.Body)
	}
	if foreignIngest.Code != 200 || !strings.Contains(foreignIngest.Body.String(), `"ingested":0`) || !strings.Contains(foreignIngest.Body.String(), `"failed":1`) {
		t.Fatalf("foreign ingest was not rejected: %d %s", foreignIngest.Code, foreignIngest.Body)
	}
	var ingestedOwner int64
	if err := s.m.traffic.DB().QueryRow(`SELECT task_id FROM exchanges WHERE url LIKE ?`, "http://"+host+"/ingested-b").Scan(&ingestedOwner); err != nil {
		t.Fatal(err)
	}
	// The operator JWT path remains intentionally unrestricted, but records an
	// operator-only owner 0 row that no task token can claim or read. A task token
	// must also never authenticate a management/read route.
	operatorJWT, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	operatorIngest := ingestWith(operatorJWT, "http://f011-operator.example.test/ingested-operator")
	var operatorOwner int64
	if err := s.m.traffic.DB().QueryRow(`SELECT task_id FROM exchanges WHERE url LIKE ?`, "http://f011-operator.example.test/ingested-operator").Scan(&operatorOwner); err != nil {
		t.Fatal(err)
	}
	readReq := httptest.NewRequest("GET", "/api/tasks", nil)
	readReq.Header.Set("Authorization", "Bearer "+tokenB)
	readRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(readRec, readReq)
	afterIngestA, _ := f010Call(t, ctxA, searchA, map[string]any{"host": host, "contains": "/ingested-b"})
	afterIngestB, _ := f010Call(t, ctxB, searchB, map[string]any{"host": host, "contains": "/ingested-b"})

	leaks := []string{headerSecret, cookieSecret, querySecret, customSecret, nestedSecret, formSecret, bodySecret, binarySecret, ownBSecret}
	ownARedacted := true
	for _, secret := range leaks {
		if strings.Contains(ownAGet, secret) {
			ownARedacted = false
		}
	}
	ownASearchRedacted := !strings.Contains(ownASearch, querySecret) && strings.Contains(ownASearch, "redacted")
	ownAContext := strings.Contains(ownAGet, `"ok":true`) && strings.Contains(ownAGet, "user=a")

	fmt.Printf("F011 same_host_cross_search=%v cross_search_perm=%s cross_get_perm=%s cross_blob_perm=%s own_search=%v own_get=%v ownA_search=%v ownA_get=%v redacted=%v search_redacted=%v binary_redacted=%v operator_raw=%v wrapper_perm=%s wrapper_call_denied=%v ingest_own=%d ingest_foreign=%d ingested_owner=%d A_sees_ingested=%v B_sees_ingested=%v\n",
		strings.Contains(crossSearch, idA), crossSearchPerm, crossGetPerm, crossBlobPerm,
		strings.Contains(ownSearch, idB), strings.Contains(ownGet, `"owner":"B"`),
		strings.Contains(ownASearch, idA), strings.Contains(ownAGet, `"ok":true`), ownARedacted, ownASearchRedacted,
		strings.Contains(ownABlob, "Binary content redacted") && !strings.Contains(ownABlob, binarySecret),
		operatorRaw, wrappedDecision.Behavior, wrappedDecision.Behavior == permission.Deny && wrappedCallPerm == permission.Deny && !strings.Contains(wrappedCall, headerSecret),
		ownIngest.Code, foreignIngest.Code, ingestedOwner,
		strings.Contains(afterIngestA, "/ingested-b"), strings.Contains(afterIngestB, "/ingested-b"))
	fmt.Printf("F011 A11 operator_ingest=%d operator_owner=%d task_token_read=%d\n", operatorIngest.Code, operatorOwner, readRec.Code)

	if strings.Contains(crossSearch, idA) {
		t.Fatalf("same-host search returned task A's exchange: %q %s", crossSearch, crossSearchPerm)
	}
	if crossGetPerm != permission.Deny || strings.Contains(crossGet, headerSecret) {
		t.Fatalf("cross-task get was not denied: %q %s", crossGet, crossGetPerm)
	}
	if crossBlobPerm != permission.Deny || strings.Contains(crossBlob, binarySecret) {
		t.Fatalf("cross-task blob was not denied: %q %s", crossBlob, crossBlobPerm)
	}
	if !strings.Contains(ownSearch, idB) || ownSearchPerm != permission.Allow || ownGetPerm != permission.Allow || !strings.Contains(ownGet, `"owner":"B"`) {
		t.Fatalf("own-task B read broke: %q %s / %q %s", ownSearch, ownSearchPerm, ownGet, ownGetPerm)
	}
	if !strings.Contains(ownASearch, idA) || ownASearchPerm != permission.Allow || !strings.Contains(ownAGet, `"ok":true`) || ownAGetPerm != permission.Allow {
		t.Fatalf("own-task A read broke: %q %s / %q %s", ownASearch, ownASearchPerm, ownAGet, ownAGetPerm)
	}
	if !ownARedacted || !ownASearchRedacted || !ownAContext {
		t.Fatalf("agent-facing redaction incomplete: get=%q search=%q", ownAGet, ownASearch)
	}
	if !strings.Contains(ownABlob, "Binary content redacted") || strings.Contains(ownABlob, binarySecret) {
		t.Fatalf("binary blob leaked to agent: %q", ownABlob)
	}
	if !operatorRaw {
		t.Fatal("operator raw traffic view lost credential material")
	}
	if wrappedDecision.Behavior != permission.Deny || wrappedCallPerm != permission.Deny || !strings.Contains(wrappedCall, "outside") {
		t.Fatalf("decorated tool bypassed scope: perm=%s call_perm=%s call=%q", wrappedDecision.Behavior, wrappedCallPerm, wrappedCall)
	}
	if ingestedOwner != taskBID || !strings.Contains(afterIngestB, "/ingested-b") || strings.Contains(afterIngestA, "/ingested-b") {
		t.Fatalf("ingest ownership mismatch: owner=%d A=%q B=%q", ingestedOwner, afterIngestA, afterIngestB)
	}
	if strings.Contains(foreignIngest.Body.String(), "ingested\":1") {
		t.Fatalf("foreign host was ingested: %s", foreignIngest.Body)
	}
	if operatorIngest.Code != 200 || operatorOwner != 0 || readRec.Code != 401 {
		t.Fatalf("A11 operator/token boundary mismatch: operator=%d owner=%d read=%d", operatorIngest.Code, operatorOwner, readRec.Code)
	}
}
