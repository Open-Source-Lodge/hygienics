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

func TestEnvSecrets(t *testing.T) {
	det, _ := detect.NewDetectorDefaultConfig()
	// high-entropy password with no known token format; only the variable
	// name marks it as a secret. Built at runtime — see the note on key.
	pw := fmt.Sprintf("%x", sha256.Sum256([]byte("hygienics-env-pw")))
	blob := fmt.Sprintf("%x", sha256.Sum256([]byte("hygienics-env-blob")))
	env := []string{
		"MY_CI_TOKEN=" + key,                    // known token format
		"DB_PASSWORD=" + pw,                     // name context only
		"PATH=/usr/bin:/bin",                    // boring
		"SECRET_SOCK=/tmp/" + pw,                // path guard
		"API_KEY=short",                         // too short
		"LC_SECRET_KEY=" + pw,                   // LC_ prefix guard
		"DB_PASSWORD_COPY=" + pw,                // dedupe
		"RANDOM_BLOB=" + blob,                   // no keyword, no rule — entropy fallback
		"GREETING=a plain sentence with spaces", // space skip
		"LOW_ENTROPY=aaaabbbbaaaabbbb",          // below threshold
	}
	got := envSecrets(env, det, 3.3)
	if len(got) != 3 {
		t.Fatalf("got %d hits: %+v", len(got), got)
	}
	if got[2].Name != "RANDOM_BLOB" || got[2].Rule != "high-entropy" || got[2].Secret != blob {
		t.Fatalf("entropy hit: %+v", got[2])
	}
	if got[0].Name != "MY_CI_TOKEN" || got[0].Rule != "github-pat" || got[0].Secret != key {
		t.Fatalf("token hit: %+v", got[0])
	}
	if got[1].Name != "DB_PASSWORD" || got[1].Secret != pw {
		t.Fatalf("password hit: %+v", got[1])
	}
}

func TestSetupCmd(t *testing.T) {
	f := t.TempDir() + "/secrets"
	os.WriteFile(f, []byte("preexisting-literal-abc123\n"), 0o600)
	t.Setenv("HYGIENICS_TEST_TOKEN", key)
	if err := setupCmd([]string{"-secrets", f}); err != nil {
		t.Fatal(err)
	}
	lits, _ := loadLiterals(f)
	found := false
	for _, l := range lits {
		if string(l) == key {
			found = true
		}
	}
	if !found || string(lits[0]) != "preexisting-literal-abc123" {
		t.Fatalf("lits=%d, key found=%v", len(lits), found)
	}
	// second run must not duplicate
	if err := setupCmd([]string{"-secrets", f}); err != nil {
		t.Fatal(err)
	}
	n := 0
	lits, _ = loadLiterals(f)
	for _, l := range lits {
		if string(l) == key {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("key appears %d times after rerun", n)
	}
}

func TestMask(t *testing.T) {
	if got := mask("short"); got != "(5 chars)" {
		t.Errorf("mask short = %q", got)
	}
	long := strings.Repeat("A", 4) + strings.Repeat("x", 16) // built at runtime, no literal token
	if got := mask(long); got != "AAAA… (20 chars)" {
		t.Errorf("mask long = %q", got)
	}
}

func TestRollingLog(t *testing.T) {
	path := t.TempDir() + "/hygienics.log"
	rl, err := openRollingLog(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		fmt.Fprintf(rl, "line %d\n", i)
	}
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > 11 { // limit 10 plus the 10% slack
		t.Fatalf("got %d lines, want <= 11", len(lines))
	}
	if last := lines[len(lines)-1]; last != "line 29" {
		t.Fatalf("last line = %q, want line 29", last)
	}
	// reopen: the counter must pick up the existing lines
	rl2, err := openRollingLog(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(rl2, "line 30")
	if rl2.count < 10 {
		t.Fatalf("count = %d after reopen, want >= 10", rl2.count)
	}
}

func TestLastLines(t *testing.T) {
	if got := string(lastLines([]byte("a\nb\nc\n"), 2)); got != "b\nc\n" {
		t.Fatalf("got %q", got)
	}
	if got := string(lastLines([]byte("a\nb\n"), 5)); got != "a\nb\n" {
		t.Fatalf("got %q", got)
	}
}
