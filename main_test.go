package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/detect"
)

const key = "ghp_1WqGjkQh7sR2v5mN8pL3xZ9cB4dF6eT0uY1aK" // fake GitHub PAT

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
	newProxy(u, &scanner{det}, false).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)))
	if rec.Code != 200 || strings.Contains(got, key) || !strings.Contains(got, "[REDACTED:github-pat:") {
		t.Fatalf("redact: code=%d upstream got %q", rec.Code, got)
	}
	// block
	got = ""
	rec = httptest.NewRecorder()
	newProxy(u, &scanner{det}, true).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)))
	if rec.Code != 422 || got != "" {
		t.Fatalf("block: code=%d upstream got %q", rec.Code, got)
	}
	// clean passthrough
	rec = httptest.NewRecorder()
	newProxy(u, &scanner{det}, true).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"messages":[]}`)))
	if rec.Code != 200 || got != `{"messages":[]}` {
		t.Fatalf("passthrough: code=%d got %q", rec.Code, got)
	}
}
