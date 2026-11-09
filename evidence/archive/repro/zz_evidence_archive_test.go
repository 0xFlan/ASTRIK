package server

// Evidence reproducer for the F-004 archive-handling review.
//
// It drives the real Server.Handler() (cors -> requireAuth -> ServeMux) with a
// valid JWT, so the archive reaches fsUploadSkill exactly as it does in
// production. Three questions are covered:
//
//  1. A 69-byte zstd frame can declare a 128 MiB window. ZipDecompressor's
//     default cap accepts it, allocating ~135 MiB of heap for one upload.
//  2. ZIP entry names with .., absolute paths, backslashes, encoded dots,
//     NUL, and doubled separators cannot write outside the temp skill root.
//  3. The task-archive tar.zst extractor rejects traversal, absolute paths,
//     symlinks, hardlinks, and unsupported entry types.
//
// Before the fix, TestSkillUploadRejectsOversizedZstdWindow fails because the
// crafted archive returns 201. After applying the 8 MiB zstd window cap, it
// returns 400 and the traversal/extractor tests remain green.
//
// Run from the ARTEX repository root:
//   cp <this file> server/zz_evidence_archive_test.go
//   go test ./server -run 'TestSkillUploadRejectsOversizedZstdWindow|TestSkillUploadTraversalMatrix|TestTaskArchiveExtractor' -count=1 -v

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"hash/crc32"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
)

type archiveEvidenceEntry struct {
	name   string
	body   []byte
	method uint16
	frame  []byte
}

// archiveEvidenceZstdFrame encodes body with a normal small window. When
// windowDescriptor is non-zero, it rewrites the frame's Window_Descriptor byte.
// 0x88 is windowLog 27 (128 MiB); 0x68 is windowLog 23 (8 MiB).
func archiveEvidenceZstdFrame(t *testing.T, body []byte, windowDescriptor byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf,
		zstd.WithWindowSize(1<<20),
		zstd.WithSingleSegment(false),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := enc.Write(body); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	if len(raw) < 6 || raw[4]&0x20 != 0 {
		t.Fatalf("unexpected frame header: %x", raw[:min(len(raw), 8)])
	}
	if windowDescriptor != 0 {
		raw[5] = windowDescriptor
	}
	return raw
}

// archiveEvidenceArchive creates a ZIP in which each zstd entry declares the
// exact uncompressed length and CRC of body while carrying frame as the raw
// method-93 payload. Other entries are ordinary Store/Deflate entries.
func archiveEvidenceArchive(t *testing.T, entries ...archiveEvidenceEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		if e.method == zipMethodZstd {
			if e.frame == nil {
				t.Fatalf("zstd entry %q has no frame", e.name)
			}
			hdr := &zip.FileHeader{
				Name:               e.name,
				Method:             zipMethodZstd,
				CompressedSize64:   uint64(len(e.frame)),
				UncompressedSize64: uint64(len(e.body)),
				CRC32:              crc32.ChecksumIEEE(e.body),
			}
			w, err := zw.CreateRaw(hdr)
			if err != nil {
				t.Fatalf("create raw %q: %v", e.name, err)
			}
			if _, err := w.Write(e.frame); err != nil {
				t.Fatalf("write raw %q: %v", e.name, err)
			}
			continue
		}
		hdr := &zip.FileHeader{Name: e.name, Method: e.method}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create %q: %v", e.name, err)
		}
		if _, err := w.Write(e.body); err != nil {
			t.Fatalf("write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func archiveEvidenceMultipart(t *testing.T, archive []byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "archive.zip")
	if err != nil {
		t.Fatalf("multipart create: %v", err)
	}
	if _, err := part.Write(archive); err != nil {
		t.Fatalf("multipart write: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	return body.Bytes(), mw.FormDataContentType()
}

type archiveEvidenceLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *archiveEvidenceLogs) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *archiveEvidenceLogs) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func archiveEvidenceServer(t *testing.T) (*httptest.Server, string, *archiveEvidenceLogs, string) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	skillDir := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{}, jwtKey: key, skillDir: skillDir}
	logs := &archiveEvidenceLogs{}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.ErrorLog = log.New(logs, "", 0)
	ts.Start()
	t.Cleanup(ts.Close)
	token, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	return ts, skillDir, logs, token
}

func archiveEvidencePost(t *testing.T, ts *httptest.Server, token string, archive []byte) (*http.Response, []byte) {
	t.Helper()
	form, contentType := archiveEvidenceMultipart(t, archive)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/skills/upload", bytes.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func archiveEvidenceHeap() (runtime.MemStats, int64) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m, int64(m.HeapAlloc)
}

// TestSkillUploadRejectsOversizedZstdWindow is the fail-before/pass-after
// regression. On the unfixed code the crafted archive returns 201 and installs
// a skill; after the fix the decoder rejects the 128 MiB window with 400 before
// allocating it.
func TestSkillUploadRejectsOversizedZstdWindow(t *testing.T) {
	ts, skillDir, logs, token := archiveEvidenceServer(t)
	body := []byte("---\nname: archive-window-probe\ndescription: probe\n---\nbody\n")
	frame := archiveEvidenceZstdFrame(t, body, 0x88) // 128 MiB window
	archive := archiveEvidenceArchive(t, archiveEvidenceEntry{
		name: "archive-window-probe/SKILL.md", body: body, method: zipMethodZstd, frame: frame,
	})
	t.Logf("archive_sha256=%x archive_bytes=%d frame_sha256=%x frame_bytes=%d",
		sha256.Sum256(archive), len(archive), sha256.Sum256(frame), len(frame))

	_, beforeHeap := archiveEvidenceHeap()
	resp, respBody := archiveEvidencePost(t, ts, token, archive)
	_, afterHeap := archiveEvidenceHeap()
	t.Logf("oversized_window status=%d content_type=%q body=%q heap_before=%d heap_after=%d heap_delta=%d",
		resp.StatusCode, resp.Header.Get("Content-Type"), string(respBody), beforeHeap, afterHeap, afterHeap-beforeHeap)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized zstd window was accepted: status=%d body=%s (want 400)", resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), "window size exceeded") {
		t.Fatalf("oversized zstd window did not name the decoder limit: body=%s", respBody)
	}
	if entries, err := os.ReadDir(skillDir); err == nil && len(entries) != 0 {
		t.Fatalf("rejected upload left files behind: %v", entries)
	}
	if strings.Contains(logs.String(), "panic serving") {
		t.Fatalf("oversized window panicked the server: %s", logs.String())
	}
	// A normal zstd archive must still install. This guards against a fix that
	// rejects legitimate WinZip method-93 skill packages.
	legitFrame := archiveEvidenceZstdFrame(t, body, 0)
	legit := archiveEvidenceArchive(t, archiveEvidenceEntry{
		name: "archive-window-probe/SKILL.md", body: body, method: zipMethodZstd, frame: legitFrame,
	})
	resp, respBody = archiveEvidencePost(t, ts, token, legit)
	t.Logf("legitimate_zstd status=%d body=%q", resp.StatusCode, string(respBody))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("legitimate zstd archive rejected: status=%d body=%s", resp.StatusCode, respBody)
	}
	if _, err := os.Stat(filepath.Join(skillDir, "archive-window-probe", "SKILL.md")); err != nil {
		t.Fatalf("legitimate zstd skill was not installed: %v", err)
	}
}

// TestSkillUploadTraversalMatrix sends each classic archive path shape through
// the authenticated production route. Every case must return 400 and leave the
// skill root empty; the canary outside the root must remain absent.
func TestSkillUploadTraversalMatrix(t *testing.T) {
	ts, skillDir, _, token := archiveEvidenceServer(t)
	base := filepath.Dir(skillDir)
	absCanary := filepath.Join(t.TempDir(), "absolute-escape.sh")
	skillBody := []byte("---\nname: archive-traversal-probe\ndescription: probe\n---\nbody\n")
	canaryBody := []byte("archive escape canary")

	cases := []struct {
		name   string
		canary string
	}{
		{"../outside.sh", filepath.Join(base, "outside.sh")},
		{"a/../../outside.sh", filepath.Join(base, "outside.sh")},
		{"..\\..\\outside.sh", ""},
		{"a//outside.sh", ""},
		{"%2e%2e/outside.sh", ""},
		{"C:/outside.sh", ""},
		{"a\x00b.sh", ""},
		{absCanary, absCanary},
	}

	for i, c := range cases {
		archive := archiveEvidenceArchive(t,
			archiveEvidenceEntry{name: "SKILL.md", body: skillBody, method: zip.Store},
			archiveEvidenceEntry{name: c.name, body: canaryBody, method: zip.Store},
		)
		if c.canary != "" {
			_ = os.Remove(c.canary)
		}
		resp, respBody := archiveEvidencePost(t, ts, token, archive)
		t.Logf("traversal case_%d name=%q archive_bytes=%d status=%d body=%q",
			i, c.name, len(archive), resp.StatusCode, string(respBody))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("case %q returned %d, want 400: %s", c.name, resp.StatusCode, respBody)
		}
		if !strings.Contains(string(respBody), "illegal path") {
			t.Fatalf("case %q did not report an illegal path: %s", c.name, respBody)
		}
		if c.canary != "" {
			if _, err := os.Stat(c.canary); !os.IsNotExist(err) {
				t.Fatalf("case %q wrote outside the skill root: %s (%v)", c.name, c.canary, err)
			}
		}
		if entries, err := os.ReadDir(skillDir); err == nil && len(entries) != 0 {
			t.Fatalf("case %q left files behind: %v", c.name, entries)
		}
	}
}

func archiveEvidenceTarZst(t *testing.T, hdr *tar.Header, body []byte) string {
	t.Helper()
	var compressed bytes.Buffer
	enc, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(enc)
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header %q: %v", hdr.Name, err)
	}
	if len(body) > 0 && (hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA) {
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar body %q: %v", hdr.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close %q: %v", hdr.Name, err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("zstd close %q: %v", hdr.Name, err)
	}
	path := filepath.Join(t.TempDir(), "crafted.tar.zst")
	if err := os.WriteFile(path, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestTaskArchiveExtractorRejectsUnsafeEntries exercises the tar.zst sink that
// restoreTaskArchive calls. Task packages are server-generated and checksummed,
// so this is defense-in-depth rather than an upload route; the observed effect
// is still a real filesystem result.
func TestTaskArchiveExtractorRejectsUnsafeEntries(t *testing.T) {
	body := []byte("archive escape canary")
	tests := []struct {
		name string
		hdr  *tar.Header
	}{
		{"dot dot", &tar.Header{Name: "../escape.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}},
		{"nested dot dot", &tar.Header{Name: "a/../../escape.txt", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}},
		{"dot", &tar.Header{Name: ".", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}},
		{"trailing dot dot", &tar.Header{Name: "a/..", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}},
		{"symlink", &tar.Header{Name: "link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		{"hardlink", &tar.Header{Name: "link", Mode: 0o600, Typeflag: tar.TypeLink, Linkname: "target"}},
		{"fifo", &tar.Header{Name: "pipe", Mode: 0o600, Typeflag: tar.TypeFifo}},
	}

	for _, tc := range tests {
		base := t.TempDir()
		destination := filepath.Join(base, "extract")
		canary := filepath.Join(base, "escape.txt")
		path := archiveEvidenceTarZst(t, tc.hdr, body)
		err := extractTaskArchivePackage(path, "", destination)
		t.Logf("tar_entry=%q type=%d name=%q status=%v", tc.name, tc.hdr.Typeflag, tc.hdr.Name, err)
		if err == nil {
			t.Fatalf("unsafe tar entry %q was accepted", tc.name)
		}
		if _, statErr := os.Stat(canary); !os.IsNotExist(statErr) {
			t.Fatalf("tar entry %q wrote outside destination: %s (%v)", tc.name, canary, statErr)
		}
	}

	// An absolute path uses a fresh canary so the test observes an attempted
	// write even if the destination is elsewhere.
	base := t.TempDir()
	destination := filepath.Join(base, "extract")
	absCanary := filepath.Join(t.TempDir(), "absolute-escape.txt")
	path := archiveEvidenceTarZst(t, &tar.Header{
		Name: absCanary, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}, body)
	err := extractTaskArchivePackage(path, "", destination)
	t.Logf("tar_absolute name=%q status=%v", absCanary, err)
	if err == nil {
		t.Fatalf("absolute tar entry was accepted")
	}
	if _, statErr := os.Stat(absCanary); !os.IsNotExist(statErr) {
		t.Fatalf("absolute tar entry wrote outside destination: %s (%v)", absCanary, statErr)
	}
}

// TestTaskArchiveExtractorRejectsForgedSize checks the 128 TiB ceiling without
// writing the declared bytes. The header alone must be rejected.
func TestTaskArchiveExtractorRejectsForgedSize(t *testing.T) {
	// Build the tar manually because tar.Writer refuses to close a header whose
	// declared size was not written.
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	hdr := &tar.Header{Name: "forged.bin", Mode: 0o600, Size: 1 << 60, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	// Deliberately do not write the body; close the zstd stream over the bytes
	// tar.Writer has flushed.
	_ = tw.Flush()
	var compressed bytes.Buffer
	enc, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "forged.tar.zst")
	if err := os.WriteFile(path, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "extract")
	err = extractTaskArchivePackage(path, "", destination)
	t.Logf("forged_size status=%v", err)
	if err == nil {
		t.Fatal("forged 1 EiB tar header was accepted")
	}
	if _, statErr := os.Stat(filepath.Join(destination, "forged.bin")); !os.IsNotExist(statErr) {
		t.Fatalf("forged-size entry created a file: %v", statErr)
	}
}
