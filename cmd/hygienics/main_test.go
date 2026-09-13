package main

import (
	"crypto/sha256"
	"fmt"
	"os"
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
