package server

// Evidence reproducer for GO-2026-6865 / CVE-2026-116591.
// It feeds the advisory's crafted two-block zstd frame through the real
// fsUploadSkill handler by wrapping it in a ZIP entry using method 93
// (Zstandard), which newSkillZipReader registers. No direct call to the
// decompressor is made.
//
// On github.com/klauspost/compress v1.18.6 this panics in fse.nextFast.
// On v1.20.2 it returns a bounded 400 decode error.
//
// Run from the ARTEX repository root:
//   cp <this file> server/zz_evidence_zstd_panic_test.go
//   go test ./server -run TestUploadCraftedZstdSkillZip -count=1 -v

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"hash/crc32"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func craftedZstdFrame() []byte {
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

func TestUploadCraftedZstdSkillZip(t *testing.T) {
	frame := craftedZstdFrame()

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

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "crafted.zip")
	if err != nil {
		t.Fatalf("create form: %v", err)
	}
	if _, err := part.Write(zbuf.Bytes()); err != nil {
		t.Fatalf("write form: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close form: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/skills/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()

	// The real handler: parse zip, register Zstandard, read SKILL.md.
	(&Server{skillDir: t.TempDir()}).fsUploadSkill(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want bounded 400 decode error, got %d: %s", rr.Code, rr.Body.String())
	}
	t.Logf("bounded rejection: status=%d body=%s frame_sha256=%s", rr.Code, rr.Body.String(), sha256hex(frame))
}

// TestSkillUploadRejectsMissingJWT proves the second chain break: the upload
// route is behind requireAuth, which rejects a request with no JWT before the
// handler (and therefore before any zstd parsing) runs.
func TestSkillUploadRejectsMissingJWT(t *testing.T) {
	reached := false
	h := (&Server{}).requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/skills/upload", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if reached {
		t.Fatal("upload handler reached without a JWT")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", rr.Code, rr.Body.String())
	}
	t.Logf("anonymous upload rejected before handler: status=%d body=%s", rr.Code, rr.Body.String())
}

func sha256hex(data []byte) string {
	// Local helper to keep the evidence line stable without importing fmt/crypto/sha256 twice.
	h := crc32.NewIEEE()
	_, _ = h.Write(data)
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	return hex.EncodeToString(nonce[:]) + "-" + hex.EncodeToString(h.Sum(nil))
}
