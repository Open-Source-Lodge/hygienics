// Package logfile is a size-bounded append-only log file.
package logfile

import (
	"bytes"
	"os"
)

// Log appends to a file and keeps only the newest limit lines.
type Log struct {
	path  string
	limit int
	f     *os.File // opened O_APPEND: writes always land at EOF, even after a trim rewrite
	count int
}

// Open opens or creates the log file at path.
func Open(path string, limit int) (*Log, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Log{path: path, limit: limit, f: f, count: bytes.Count(data, []byte("\n"))}, nil
}

func (r *Log) Write(p []byte) (int, error) {
	n, err := r.f.Write(p)
	r.count += bytes.Count(p[:n], []byte("\n"))
	// ponytail: 10% slack so the O(file) trim rewrite amortizes instead of
	// firing on every line once the file is full.
	if err == nil && r.count > r.limit+r.limit/10 {
		err = r.trim()
	}
	return n, err
}

// trim rewrites the file with only the last limit lines.
func (r *Log) trim() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.path, LastLines(data, r.limit), 0o600); err != nil {
		return err
	}
	r.count = r.limit
	return nil
}

// LastLines returns the last n lines of data.
func LastLines(data []byte, n int) []byte {
	for extra := bytes.Count(data, []byte("\n")) - n; extra > 0; extra-- {
		data = data[bytes.IndexByte(data, '\n')+1:]
	}
	return data
}
