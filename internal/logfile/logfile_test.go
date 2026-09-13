package logfile

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRollingLog(t *testing.T) {
	path := t.TempDir() + "/hygienics.log"
	rl, err := Open(path, 10)
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
	rl2, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(rl2, "line 30")
	if rl2.count < 10 {
		t.Fatalf("count = %d after reopen, want >= 10", rl2.count)
	}
}

func TestLastLines(t *testing.T) {
	if got := string(LastLines([]byte("a\nb\nc\n"), 2)); got != "b\nc\n" {
		t.Fatalf("got %q", got)
	}
	if got := string(LastLines([]byte("a\nb\n"), 5)); got != "a\nb\n" {
		t.Fatalf("got %q", got)
	}
}
