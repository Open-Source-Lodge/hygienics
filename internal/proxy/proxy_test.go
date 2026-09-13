package proxy

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/detect"

	"hygienics/internal/scan"
)

// key is a fake GitHub PAT, built at runtime so the literal never appears in
// source or logs (a redacting proxy would strip it from both).
var key = "ghp_" + fmt.Sprintf("%x", sha256.Sum256([]byte("hygienics-test")))[:36]

func TestProxy(t *testing.T) {
	det, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	body := `{"messages":[{"role":"user","content":"token is ` + key + ` ok"}]}`

	// redact
	rec := httptest.NewRecorder()
	New(u, &scan.Scanner{Det: det}, false).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)))
	if rec.Code != 200 || strings.Contains(got, key) || !strings.Contains(got, "[REDACTED:github-pat:") {
		t.Fatalf("redact: code=%d upstream got %q", rec.Code, got)
	}
	// block
	got = ""
	rec = httptest.NewRecorder()
	New(u, &scan.Scanner{Det: det}, true).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)))
	if rec.Code != 422 || got != "" {
		t.Fatalf("block: code=%d upstream got %q", rec.Code, got)
	}
	// clean passthrough
	rec = httptest.NewRecorder()
	New(u, &scan.Scanner{Det: det}, true).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"messages":[]}`)))
	if rec.Code != 200 || got != `{"messages":[]}` {
		t.Fatalf("passthrough: code=%d got %q", rec.Code, got)
	}
}
