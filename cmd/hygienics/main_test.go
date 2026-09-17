package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	"hygienics/internal/scan"
)

// key is a fake GitHub PAT, built at runtime so the literal never appears in
// source or logs (a redacting proxy would strip it from both).
var key = "ghp_" + fmt.Sprintf("%x", sha256.Sum256([]byte("hygienics-test")))[:36]

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
	if lits, _ := scan.LoadLiterals(f); len(lits) != 1 || string(lits[0]) != val {
		t.Fatalf("lits=%q", lits)
	}
	if err := run("remove"); err != nil {
		t.Fatal(err)
	}
	if lits, _ := scan.LoadLiterals(f); len(lits) != 0 {
		t.Fatalf("after remove: %q", lits)
	}
	if err := run("remove"); err == nil {
		t.Fatal("expected not-found error")
	}
	if err := secretCmd([]string{"-secrets", f, "add", val}); err == nil {
		t.Fatal("expected refusal of secret argument")
	}
}

// TestLoadSecretsOptIn guards the rule that the proxy reads secrets only from
// the secrets file unless the user opts in.
func TestLoadSecretsOptIn(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(home+"/.ssh", 0o700)
	line := strings.Repeat("QUJD", 16)
	os.WriteFile(home+"/.ssh/id_test", []byte("-----BEGIN KEY-----\n"+line+"\n-----END KEY-----\n"), 0o600)
	secrets := home + "/secrets"
	os.WriteFile(secrets, []byte("from-secrets-file-abc123\n"), 0o600)

	lits, err := loadSecrets(secrets, secrets, home, false)
	if err != nil || len(lits) != 1 || string(lits[0]) != "from-secrets-file-abc123" {
		t.Fatalf("discover=false must read only the secrets file: %q %v", lits, err)
	}
	lits, err = loadSecrets(secrets, secrets, home, true)
	if err != nil || len(lits) != 2 || string(lits[1]) != line {
		t.Fatalf("discover=true must add the key file: %q %v", lits, err)
	}
	if _, err := loadSecrets(home+"/missing", home+"/missing", home, false); err != nil {
		t.Fatalf("missing default secrets file must be fine: %v", err)
	}
	if _, err := loadSecrets(home+"/missing", home+"/other", home, false); err == nil {
		t.Fatal("missing explicit -secrets path must be an error")
	}
}

func TestDiscoverInConfig(t *testing.T) {
	f := t.TempDir() + "/rules.toml"
	os.WriteFile(f, []byte("discover = true\n[extend]\nuseDefault = true\n"), 0o600)
	if !discoverInConfig(f) {
		t.Fatal("discover = true not read from config")
	}
	if _, err := scan.NewDetector(f); err != nil {
		t.Fatalf("gitleaks loader must accept the discover key: %v", err)
	}
	if discoverInConfig("") || discoverInConfig(f+".missing") {
		t.Fatal("empty or missing path must be false")
	}
}

func TestSetupCmd(t *testing.T) {
	f := t.TempDir() + "/secrets"
	os.WriteFile(f, []byte("preexisting-literal-abc123\n"), 0o600)
	t.Setenv("HYGIENICS_TEST_TOKEN", key)
	if err := setupCmd([]string{"-secrets", f}); err != nil {
		t.Fatal(err)
	}
	lits, _ := scan.LoadLiterals(f)
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
	lits, _ = scan.LoadLiterals(f)
	for _, l := range lits {
		if string(l) == key {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("key appears %d times after rerun", n)
	}
}
