package server

// Evidence reproducer for the F-003 auth-boundary question.
//
// It starts the real Server.Handler() (the same cors -> requireAuth -> mux stack
// used by cmd/artex) on a real loopback HTTP listener. Every anonymous request
// carries the crafted method-93 zstd archive, so if a traversal, route-alias, or
// token-parsing bypass reaches fsUploadSkill, compress 1.18.6 panics and the
// request fails instead of returning 401. A valid-token control then proves the
// same archive reaches the upload handler.
//
// Run from the ARTEX repository root:
//   cp <this file> server/zz_evidence_auth_boundary_test.go
//   go test ./server -run 'TestAuthBoundary|TestAuthenticatedCraftedZip' -count=1 -v
//
// v1.18.6: the valid-token control panics in fse.nextFast (recovered by net/http).
// v1.20.2: the same control returns 400 "corrupt input: weights tableLog too big".

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"hash/crc32"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// authBoundaryFrame is the two-block frame from GHSA-fpmh-frq8-7rj8.
func authBoundaryFrame() []byte {
	oneFrame := bytes.Join([][]byte{
		{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x74, 0x06, 0x00, 0x42, 0xb8, 0x32, 0x0d, 0x1a, 0x00, 0x00, 0x00, 0x90, 0xaf, 0xfa, 0xff, 0x03, 0x00, 0x80, 0xff, 0x7f},
		bytes.Repeat([]byte{0xa5, 0x94, 0x52, 0x4a, 0x29}, 37),
		{0xa5, 0x94, 0x12, 0x00, 0xad, 0x56, 0x03, 0xee, 0xff, 0xdf, 0xb3, 0x1a, 0x1c, 0x1a, 0x00, 0xe0, 0xff, 0x1f, 0x0f, 0xb1, 0x9c, 0x5a, 0xcf, 0x4d, 0xe4, 0x1d, 0x7b, 0xab, 0x99, 0x5e, 0x01, 0x51, 0xa4, 0x73, 0xd8, 0xb1, 0xf3, 0x39, 0x4b, 0x67, 0xf6, 0xab, 0x1a, 0xab, 0x1a, 0xab, 0x1a},
		bytes.Repeat([]byte{0x8c, 0x31, 0xc6, 0x18, 0x63}, 1365),
		{0x8c, 0x31},
		bytes.Repeat([]byte{0x63, 0x8c, 0x31, 0xc6, 0x18}, 1365),
		{0x63, 0x2c},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
		{0x31, 0x46},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365),
		{0x31, 0x06, 0x00},
	}, nil)
	return oneFrame
}

// authBoundaryZip wraps the frame in a ZIP entry using method 93, which
// newSkillZipReader registers as zstd.
func authBoundaryZip(t *testing.T) []byte {
	t.Helper()
	frame := authBoundaryFrame()
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	hdr := &zip.FileHeader{Name: "SKILL.md", Method: 93}
	hdr.CompressedSize64 = uint64(len(frame))
	hdr.UncompressedSize64 = 1 << 20
	hdr.CRC32 = crc32.ChecksumIEEE(frame)
	w, err := zw.CreateRaw(hdr)
	if err != nil {
		t.Fatalf("create raw zip entry: %v", err)
	}
	if _, err := w.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return zbuf.Bytes()
}

func authBoundaryMultipart(t *testing.T, archive []byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "crafted.zip")
	if err != nil {
		t.Fatalf("create form: %v", err)
	}
	if _, err := part.Write(archive); err != nil {
		t.Fatalf("write form: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close form: %v", err)
	}
	return body.Bytes(), mw.FormDataContentType()
}

type authBoundaryLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *authBoundaryLogs) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *authBoundaryLogs) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// authBoundaryServer starts the real route stack. Manager is empty only because
// these paths do not need PostgreSQL; requireAuth, cors, ServeMux and
// fsUploadSkill are the production implementations.
func authBoundaryServer(t *testing.T) (*httptest.Server, *authBoundaryLogs, []byte) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{m: &Manager{}, jwtKey: key, skillDir: t.TempDir()}
	logs := &authBoundaryLogs{}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.ErrorLog = log.New(logs, "", 0)
	ts.Start()
	t.Cleanup(ts.Close)
	return ts, logs, key
}

func authBoundaryClient(ts *httptest.Server) *http.Client {
	c := ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

func authBoundaryDo(t *testing.T, c *http.Client, method, rawURL string, body []byte, contentType string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, rdr)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, rawURL, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, rawURL, err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, respBody
}

// TestAuthBoundaryAnonymousImportRoutesRejected sends the crafted archive, with
// no valid credential, to every import-route shape that has bypassed a
// path-prefix auth check in real applications. Each response is logged with its
// status, Location, Content-Type, and body. The test fails if any request
// reaches fsUploadSkill (400/409/500) or panics.
func TestAuthBoundaryAnonymousImportRoutesRejected(t *testing.T) {
	ts, logs, _ := authBoundaryServer(t)
	archive := authBoundaryZip(t)
	form, ct := authBoundaryMultipart(t, archive)
	t.Logf("archive_sha256=%x bytes=%d", sha256.Sum256(archive), len(archive))

	type probe struct {
		name   string
		method string
		path   string
		body   []byte
		ctype  string
		header map[string]string
	}
	probes := []probe{
		{"canonical upload", http.MethodPost, "/api/skills/upload", form, ct, nil},
		{"dot-dot auth prefix", http.MethodPost, "/api/auth/../api/skills/upload", form, ct, nil},
		{"dot-dot to skills", http.MethodPost, "/api/auth/../skills/upload", form, ct, nil},
		{"encoded dot-dot", http.MethodPost, "/api/auth/%2e%2e/skills/upload", form, ct, nil},
		{"encoded dot-dot and slash", http.MethodPost, "/api/auth/%2e%2e%2fskills%2fupload", form, ct, nil},
		{"health prefix my traversal", http.MethodPost, "/api/health/../skills/upload", form, ct, nil},
		{"double slash", http.MethodPost, "/api//skills/upload", form, ct, nil},
		{"trailing slash", http.MethodPost, "/api/skills/upload/", form, ct, nil},
		{"uppercase api", http.MethodPost, "/API/skills/upload", form, ct, nil},
		{"empty query token", http.MethodPost, "/api/skills/upload?token=", form, ct, nil},
		{"empty bearer", http.MethodPost, "/api/skills/upload", form, ct, map[string]string{"Authorization": "Bearer "}},
		{"empty cookie", http.MethodPost, "/api/skills/upload", form, ct, map[string]string{"Cookie": "artex_token="}},
		{"alg none", http.MethodPost, "/api/skills/upload", form, ct, map[string]string{"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJBUlRFWCJ9."}},
		{"RS256 header", http.MethodPost, "/api/skills/upload", form, ct, map[string]string{"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBUlRFWCJ9.invalid"}},
		{"wrong-key HS256", http.MethodPost, "/api/skills/upload", form, ct, map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBUlRFWCIsImV4cCI6NDEwMjQ0NDgwMH0.7r_L0e4m7V0y0Z1kZ1kZ1kZ1kZ1kZ1kZ1kZ1kZ1kZ0"}},
		{"task archive restore", http.MethodPost, "/api/task-archives/1/restore", form, ct, nil},
		{"task archive batch restore", http.MethodPost, "/api/task-archives/restore/batch", form, ct, nil},
		{"options preflight", http.MethodOptions, "/api/skills/upload", nil, "", nil},
		{"public health", http.MethodGet, "/api/health", nil, "", nil},
		{"auth status exempt", http.MethodGet, "/api/auth/status", nil, "", nil},
	}

	c := authBoundaryClient(ts)
	for _, p := range probes {
		resp, body := authBoundaryDo(t, c, p.method, ts.URL+p.path, p.body, p.ctype, p.header)
		t.Logf("%-32s %s %-42s -> %d location=%q content-type=%q body=%q",
			p.name, p.method, p.path, resp.StatusCode, resp.Header.Get("Location"), resp.Header.Get("Content-Type"), string(body))

		if p.name == "public health" || p.name == "auth status exempt" || p.name == "options preflight" {
			continue // deliberately public/exempt; neither is an import handler
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
			http.StatusMethodNotAllowed, http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			// Rejected before fsUploadSkill.
		default:
			t.Fatalf("%s: status=%d reached an unexpected handler (want 401/403/404/405/301/308); body=%s logs=%s",
				p.name, resp.StatusCode, body, logs.String())
		}
	}
	if strings.Contains(logs.String(), "panic serving") {
		t.Fatalf("anonymous request panicked the upload handler: %s", logs.String())
	}

	// A browser or proxy that follows the 307 must still hit the JWT boundary.
	// The redirect lands on the canonical route, where requireAuth returns 401.
	follow := &http.Client{Transport: ts.Client().Transport} // fresh client: default redirect policy
	for _, path := range []string{"/api/auth/../skills/upload", "/api/health/../skills/upload", "/api//skills/upload"} {
		resp, body := authBoundaryDo(t, follow, http.MethodPost, ts.URL+path, form, ct, nil)
		t.Logf("follow-redirect %-32s -> %d final=%q content-type=%q body=%q", path, resp.StatusCode, resp.Request.URL.Path, resp.Header.Get("Content-Type"), string(body))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("follow-redirect %s: final status=%d want 401; body=%s", path, resp.StatusCode, body)
		}
	}
}

// TestAuthenticatedCraftedZipReachesUpload is the positive control. A valid JWT
// must get past requireAuth and reach fsUploadSkill: on 1.18.6 the server recovers
// a panic, on 1.20.2 it returns the bounded decode error. A 401 here would mean the
// token path is broken; a 200 would mean the archive was accepted.
func TestAuthenticatedCraftedZipReachesUpload(t *testing.T) {
	ts, logs, key := authBoundaryServer(t)
	token, err := signJWT(key)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	archive := authBoundaryZip(t)
	form, ct := authBoundaryMultipart(t, archive)

	resp, body := func() (*http.Response, []byte) {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/skills/upload", bytes.NewReader(form))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := authBoundaryClient(ts).Do(req)
		if err != nil {
			return nil, []byte(err.Error())
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, b
	}()

	if resp == nil {
		// net/http recovers handler panics and closes the connection. Give the
		// ErrorLog goroutine a moment, then require the panic signature.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && !strings.Contains(logs.String(), "panic serving") {
			time.Sleep(20 * time.Millisecond)
		}
		if strings.Contains(logs.String(), "panic serving") && strings.Contains(logs.String(), "index out of range") {
			t.Logf("authenticated archive reached fsUploadSkill and panicked (expected on compress 1.18.6): %s", logs.String())
			return
		}
		t.Fatalf("authenticated request failed without the expected compress panic: body=%s logs=%s", body, logs.String())
	}
	t.Logf("authenticated upload -> %d content-type=%q body=%q", resp.StatusCode, resp.Header.Get("Content-Type"), string(body))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("authenticated crafted archive: status=%d want 400 (1.20.2) or a recovered 1.18.6 panic; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "corrupt input") {
		t.Fatalf("authenticated upload did not reach the zstd decoder: body=%s", body)
	}
	if strings.Contains(logs.String(), "panic serving") {
		t.Fatalf("fixed compress version still panicked: %s", logs.String())
	}
}
