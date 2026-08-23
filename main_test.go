package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/detect"
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
	newProxy(u, &scanner{det: det}, false).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)))
	if rec.Code != 200 || strings.Contains(got, key) || !strings.Contains(got, "[REDACTED:github-pat:") {
		t.Fatalf("redact: code=%d upstream got %q", rec.Code, got)
	}
	// block
	got = ""
	rec = httptest.NewRecorder()
	newProxy(u, &scanner{det: det}, true).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body)))
	if rec.Code != 422 || got != "" {
		t.Fatalf("block: code=%d upstream got %q", rec.Code, got)
	}
	// clean passthrough
	rec = httptest.NewRecorder()
	newProxy(u, &scanner{det: det}, true).ServeHTTP(rec, httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{"messages":[]}`)))
	if rec.Code != 200 || got != `{"messages":[]}` {
		t.Fatalf("passthrough: code=%d got %q", rec.Code, got)
	}
}

func TestLiteralSecret(t *testing.T) {
	det, _ := detect.NewDetectorDefaultConfig()
	s := &scanner{det: det, literals: [][]byte{[]byte("abc123")}}
	out, hits := s.scan([]byte(`{"content":"the password is abc123, use it twice: abc123"}`))
	if len(hits) != 1 || hits[0].RuleID != "literal" {
		t.Fatalf("hits=%v", hits)
	}
	if strings.Contains(string(out), "abc123") || strings.Count(string(out), "[REDACTED:literal:") != 2 {
		t.Fatalf("out=%s", out)
	}
}

func TestCustomRuleConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := dir + "/rules.toml"
	os.WriteFile(cfg, []byte(`
[extend]
useDefault = true

[[rules]]
id = "acme-token"
description = "ACME internal token"
regex = '''acme-[a-z0-9]{12}'''
`), 0o600)
	det, err := newDetector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &scanner{det: det}
	// custom rule fires
	out, hits := s.scan([]byte(`{"content":"token acme-x1y2z3a4b5c6 here"}`))
	if len(hits) != 1 || hits[0].RuleID != "acme-token" || strings.Contains(string(out), "acme-x1y2z3a4b5c6") {
		t.Fatalf("hits=%v out=%s", hits, out)
	}
	// default rules still extend through
	if _, hits = s.scan([]byte(`{"c":"` + key + `"}`)); len(hits) != 1 || hits[0].RuleID != "github-pat" {
		t.Fatalf("default rules lost: %v", hits)
	}
}

func TestLoadLiterals(t *testing.T) {
	f := t.TempDir() + "/secrets"
	os.WriteFile(f, []byte("# comment\nabc123\n\n  spaced  \n"), 0o600)
	lits, err := loadLiterals(f)
	if err != nil || len(lits) != 2 || string(lits[0]) != "abc123" || string(lits[1]) != "spaced" {
		t.Fatalf("lits=%q err=%v", lits, err)
	}
}

func TestSecretCmd(t *testing.T) {
	f := t.TempDir() + "/secrets"
	val := "example-literal-abc123"
	run := func(verb string) error { // feed the secret on stdin, as the prompt does
		in, _ := os.CreateTemp(t.TempDir(), "stdin")
		in.WriteString(val + "\n")
		in.Seek(0, 0)
		defer in.Close()
		orig := os.Stdin
		os.Stdin = in
		defer func() { os.Stdin = orig }()
		return secretCmd([]string{"-secrets", f, verb})
	}
	for range 2 { // second add must dedupe
		if err := run("add"); err != nil {
			t.Fatal(err)
		}
	}
	if lits, _ := loadLiterals(f); len(lits) != 1 || string(lits[0]) != val {
		t.Fatalf("lits=%q", lits)
	}
	if err := run("remove"); err != nil {
		t.Fatal(err)
	}
	if lits, _ := loadLiterals(f); len(lits) != 0 {
		t.Fatalf("after remove: %q", lits)
	}
	if err := run("remove"); err == nil {
		t.Fatal("expected not-found error")
	}
	if err := secretCmd([]string{"-secrets", f, "add", val}); err == nil {
		t.Fatal("expected refusal of secret argument")
	}
}
