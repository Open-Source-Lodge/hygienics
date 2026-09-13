package scan

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/detect"
)

// key is a fake GitHub PAT, built at runtime so the literal never appears in
// source or logs (a redacting proxy would strip it from both).
var key = "ghp_" + fmt.Sprintf("%x", sha256.Sum256([]byte("hygienics-test")))[:36]

func TestLiteralSecret(t *testing.T) {
	det, _ := detect.NewDetectorDefaultConfig()
	s := &Scanner{Det: det, Literals: [][]byte{[]byte("abc123")}}
	out, hits := s.Scan([]byte(`{"content":"the password is abc123, use it twice: abc123"}`))
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
	det, err := NewDetector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Scanner{Det: det}
	// custom rule fires
	out, hits := s.Scan([]byte(`{"content":"token acme-x1y2z3a4b5c6 here"}`))
	if len(hits) != 1 || hits[0].RuleID != "acme-token" || strings.Contains(string(out), "acme-x1y2z3a4b5c6") {
		t.Fatalf("hits=%v out=%s", hits, out)
	}
	// default rules still extend through
	if _, hits = s.Scan([]byte(`{"c":"` + key + `"}`)); len(hits) != 1 || hits[0].RuleID != "github-pat" {
		t.Fatalf("default rules lost: %v", hits)
	}
}

func TestLoadLiterals(t *testing.T) {
	f := t.TempDir() + "/secrets"
	os.WriteFile(f, []byte("# comment\nabc123\n\n  spaced  \n"), 0o600)
	lits, err := LoadLiterals(f)
	if err != nil || len(lits) != 2 || string(lits[0]) != "abc123" || string(lits[1]) != "spaced" {
		t.Fatalf("lits=%q err=%v", lits, err)
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
	got := EnvSecrets(env, det, 3.3)
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

func TestMask(t *testing.T) {
	if got := Mask("short"); got != "(5 chars)" {
		t.Errorf("Mask short = %q", got)
	}
	long := strings.Repeat("A", 4) + strings.Repeat("x", 16) // built at runtime, no literal token
	if got := Mask(long); got != "AAAA… (20 chars)" {
		t.Errorf("Mask long = %q", got)
	}
}

func TestKeyFileLiterals(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	line := strings.Repeat("QUJD", 16)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"+line+"\nc2hvcnQ=\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte("ssh-ed25519 "+line+" me@host\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".aws", "credentials"), []byte("[default]\naws_secret_access_key = "+line+"X\naws_session_token = \""+line+"J\",\n"), 0o600)
	os.MkdirAll(filepath.Join(home, ".docker"), 0o700)
	os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte("{\n  \"auths\": {\"r\": {\"auth\": \""+line+"D\"}}\n}\n"), 0o600)
	got := KeyFileLiterals(home)
	want := []string{line + "X", line + "J", line + "D", line}
	if len(got) != len(want) {
		t.Fatalf("got %d Literals, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("literal %d = %q, want %q", i, got[i], want[i])
		}
	}
}
