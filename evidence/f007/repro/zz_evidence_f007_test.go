package server

// Evidence reproducer for F-007.
//
// 1. Archive restore: the pre-F-007 install checked the destination lexically,
//    wrote the restore journal, then called os.MkdirAll/os.Rename on the same
//    re-resolved path. The probe waits for the journal (which is written after
//    the check and before the first rename) and swaps <dataDir>/tasks for a link
//    to an outside directory. A vulnerable install follows that link and writes
//    outside; the single-root install refuses it.
//
// 2. Agent MCP chain: create_mcp is bound to the Auto agent and its permission
//    is unconditionally Allowed. A stdio MCP command is spawned by connectMCP
//    during startup discovery, while ordinary MCP tool calls are AskUser-gated.
//    The probe creates a stdio MCP through the real platform tool, then runs the
//    same discovery path and checks whether the command executed.
//
// Run from the ARTEX repository root with the disposable PostgreSQL:
//   ARTEX_PG_DSN='postgres://flan@127.0.0.1:55432/artex_test?sslmode=disable' \
//     go test ./server -run 'TestF007' -count=1 -v

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestF007ArchiveRestoreDestinationFlip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	dataDir := t.TempDir()
	outside := t.TempDir()
	extracted := filepath.Join(dataDir, "archives", "tasks", ".restore", "f007-flip")
	source := filepath.Join(extracted, "files", "tasks", "42", "artifact.txt")
	transcripts := filepath.Join(extracted, "files", "transcripts")
	tasksDir := filepath.Join(dataDir, "tasks")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(transcripts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}

	const attempts = 20
	escaped := 0
	for attempt := 0; attempt < attempts; attempt++ {
		_ = os.RemoveAll(filepath.Join(outside, "42"))
		_ = os.RemoveAll(tasksDir)
		if err := os.MkdirAll(tasksDir, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.RemoveAll(filepath.Join(dataDir, "transcripts"))
		if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte("ARTEX-F007"), 0o600); err != nil {
			t.Fatal(err)
		}
		// A larger journal keeps the write/sync window open long enough for the
		// flipper to replace tasks/ after the destination check.
		for i := 0; i < 512; i++ {
			if err := os.WriteFile(filepath.Join(transcripts, fmt.Sprintf("t%03d.jsonl", i)), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		journal := filepath.Join(extracted, "restore-journal.json")
		_ = os.Remove(journal)

		stop := make(chan struct{})
		swapped := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := os.Stat(journal); err == nil {
					_ = os.RemoveAll(tasksDir)
					_ = os.Symlink(outside, tasksDir)
					close(swapped)
					return
				}
				time.Sleep(50 * time.Microsecond)
			}
		}()

		stage, installErr := installTaskArchiveFiles(dataDir, extracted, "42", 1)
		select {
		case <-swapped:
		case <-time.After(500 * time.Millisecond):
		}
		close(stop)

		if _, err := os.Stat(filepath.Join(outside, "42", "artifact.txt")); err == nil {
			escaped++
			t.Logf("attempt %d: destination link redirected the restore outside (installErr=%v)", attempt, installErr)
		}
		if stage != nil {
			_ = stage.rollback()
		}
	}
	if escaped > 0 {
		t.Errorf("F-007 GAP: archive restore followed a destination symlink swapped after the check (%d/%d attempts)", escaped, attempts)
	} else {
		t.Logf("no outside write across %d destination-symlink flips", attempts)
	}
}

func f007PlatformTool(t *testing.T, s *Server, name string) actool.CoreTool {
	t.Helper()
	for _, tool := range s.platformTools() {
		if tool.Name() == name {
			return tool
		}
	}
	t.Fatalf("platform tool %q not found", name)
	return nil
}

func TestF007AgentMCPStdioChain(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	create := f007PlatformTool(t, s, "create_mcp")

	marker := filepath.Join(t.TempDir(), "f007-stdio-ran")
	name := fmt.Sprintf("f007-chain-%d", os.Getpid())
	httpName := name + "-http"
	for _, n := range []string{name, httpName} {
		_, _ = m.pg.Exec(`DELETE FROM mcp_servers WHERE name=$1`, n)
	}
	// Registered after defer m.Close, so LIFO runs this while the pool is open.
	defer func() {
		for _, n := range []string{name, httpName} {
			_, _ = m.pg.Exec(`DELETE FROM mcp_servers WHERE name=$1`, n)
		}
		_ = os.Remove(marker)
	}()

	input := map[string]any{
		"name": name, "transport": "stdio", "command": "/bin/sh",
		"args": []string{"-c", "printf ARTEX-F007 > " + marker}, "enabled": true,
	}
	raw, _ := json.Marshal(input)
	res, err := create.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("create_mcp: %v", err)
	}
	if res.IsError {
		t.Logf("F-007 chain blocked at create_mcp: %s", res.Flatten())
	} else {
		t.Logf("F-007 create_mcp accepted stdio: %s", res.Flatten())
		rows, err := m.pg.ListMCP()
		if err != nil {
			t.Fatal(err)
		}
		var row *db.MCPServer
		for _, candidate := range rows {
			if candidate.Name == name {
				row = candidate
				break
			}
		}
		if row == nil {
			t.Fatalf("created stdio MCP %q not found", name)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		discoverErr := s.discoverAndCacheMCP(ctx, row)
		cancel()
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Errorf("F-007 GAP: agent-authored stdio MCP command executed on discovery (discoverErr=%v)", discoverErr)
		} else {
			t.Logf("agent-authored stdio MCP did not execute on discovery (discoverErr=%v)", discoverErr)
		}
	}

	// Positive control: the same agent tool still accepts an http MCP.
	httpRaw, _ := json.Marshal(map[string]any{
		"name": httpName, "transport": "http", "url": "http://127.0.0.1:1/mcp", "enabled": false,
	})
	httpRes, err := create.Call(context.Background(), httpRaw, nil)
	if err != nil {
		t.Fatalf("create_mcp http: %v", err)
	}
	if httpRes.IsError {
		t.Errorf("positive control: agent create_mcp rejected http: %s", httpRes.Flatten())
	} else {
		t.Logf("positive control: create_mcp http accepted: %s", httpRes.Flatten())
	}
}
