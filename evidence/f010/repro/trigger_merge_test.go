package server

import (
	"fmt"
	"strings"
	"testing"
)

// A long task goal repeated per event was the dominant bloat. These tests pin the
// fix: the task-context header (description + goal) is rendered ONCE per task, no
// matter how many same-task fires are merged.

const longGoal = "Obtain the protected flag of challenge f2-05 and submit it via submit_flag; the ciphertext of this challenge has highly converged, and the flag can only be derived from binary-embedded data..." // stands in for the thousands of characters of inherited facts

func sameTaskFires(n int) []triggeredRun {
	items := make([]triggeredRun, n)
	for i := range items {
		items[i] = triggeredRun{
			agentKey: "tec_benchmark", taskID: 72, taskDesc: "f2-05 reverse engineering", taskGoal: longGoal,
			message: "[Triggered by tool call]\nTool: submit_flag\nArgs: {...}\nResult: {correct:false}", mergeable: true,
		}
	}
	return items
}

func TestMergeAllRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeAllRuns(sameTaskFires(39))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a merged-all run, got %d", got)
	}
	if strings.Count(out.message, "── trigger ") < 1 || !strings.Contains(out.message, "trigger 39") {
		t.Fatalf("all 39 event bodies should be present: %q", out.message)
	}
	// A merged run embeds its header inline, so finalTriggerMessage must not re-add it.
	if out.taskDesc != "" || out.taskGoal != "" {
		t.Fatalf("merged run must clear taskDesc/taskGoal to avoid a duplicate header")
	}
	if finalTriggerMessage(out) != out.message {
		t.Fatalf("finalTriggerMessage must not prepend another header for a merged run")
	}
}

func TestMergeAllRunsGroupsInterleavedTasks(t *testing.T) {
	// Fires from two tasks arriving interleaved (A,B,A,B) must still carry each
	// task's context exactly once — grouping, not per-event repetition.
	mk := func(id int64, goal string) triggeredRun {
		return triggeredRun{agentKey: "a", taskID: id, taskDesc: "d", taskGoal: goal, message: "body", mergeable: true}
	}
	out := mergeAllRuns([]triggeredRun{mk(1, "GOAL_A"), mk(2, "GOAL_B"), mk(1, "GOAL_A"), mk(2, "GOAL_B")})
	if got := strings.Count(out.message, "GOAL_A"); got != 1 {
		t.Fatalf("task #1 goal should appear once despite interleaving, got %d", got)
	}
	if got := strings.Count(out.message, "GOAL_B"); got != 1 {
		t.Fatalf("task #2 goal should appear once despite interleaving, got %d", got)
	}
	if !strings.Contains(out.message, "across 2 tasks") {
		t.Fatalf("header should report 2 tasks: %q", out.message)
	}
	if got := strings.Count(out.message, "── trigger "); got != 4 {
		t.Fatalf("all 4 event bodies should be present, got %d", got)
	}
}

func TestMergeTriggeredRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeTriggeredRuns(sameTaskFires(5))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a by-task merge, got %d", got)
	}
}

func TestFinalTriggerMessageSingleFirePrependsHeaderOnce(t *testing.T) {
	item := sameTaskFires(1)[0]
	msg := finalTriggerMessage(item)
	if got := strings.Count(msg, longGoal); got != 1 {
		t.Fatalf("single fire should carry the task goal exactly once, got %d", got)
	}
	if !strings.HasPrefix(msg, "[Task #72") {
		t.Fatalf("single fire should be prefixed with the task-context header: %q", msg)
	}
}

func TestTaskContextHeaderEmptyForIntervalFire(t *testing.T) {
	if h := taskContextHeader(0, "", ""); h != "" {
		t.Fatalf("interval/none trigger (no task) must produce no header, got %q", h)
	}
	// An interval fire's message must pass through untouched.
	item := triggeredRun{message: "interval trigger body"}
	if finalTriggerMessage(item) != "interval trigger body" {
		t.Fatalf("interval fire message must pass through unchanged")
	}
}

// F-010 evidence: merge_mode=all folds several tasks into one run but keeps the
// FIRST task's RunInfo. F-009's scope check therefore treats later tasks in the
// merged body as cross-task and rejects a reporter tool call against them; it
// cannot use the merge to promote a later task into its scope.
func TestF010MergeAllKeepsFirstTaskScope(t *testing.T) {
	items := []triggeredRun{
		{agentKey: "reporter", taskID: 101, taskDesc: "A", taskGoal: "task A", message: "event A", mergeable: true},
		{agentKey: "reporter", taskID: 202, taskDesc: "B", taskGoal: "task B", message: "event B", mergeable: true},
	}
	out := mergeAllRuns(items)
	fmt.Printf("F010 merge_all first_task=%d contains_task_202=%v contains_task_101=%v\n",
		out.taskID, strings.Contains(out.message, "task#202"), strings.Contains(out.message, "task#101"))
	if out.taskID != 101 {
		t.Fatalf("merged run task = %d, want first task 101", out.taskID)
	}
	if !strings.Contains(out.message, "task#101") || !strings.Contains(out.message, "task#202") {
		t.Fatalf("merged message lost a task: %q", out.message)
	}
}

func TestTaskContextHeaderTruncatesLongGoal(t *testing.T) {
	huge := strings.Repeat("x", 5000)
	h := taskContextHeader(72, "d", huge)
	if len([]rune(h)) > 800 { // 200 desc + 500 goal + truncation marker/decoration, far below 5000
		t.Fatalf("header should be bounded even for a huge goal, got %d runes", len([]rune(h)))
	}
}
