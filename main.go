// hygienics: local reverse proxy for Claude Code that scans every outbound
// Messages API request for secrets before it leaves the machine.
//
//	export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	glconfig "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

const version = "0.1.0"

type scanner struct {
	det      *detect.Detector
	literals [][]byte // exact strings that must never leave the machine
}

type hit struct{ RuleID, Secret string }

// mask gives a safe preview of a secret: the first 4 characters and the
// length. Enough to identify it, never enough to leak it.
func mask(s string) string {
	if len(s) <= 8 {
		return fmt.Sprintf("(%d chars)", len(s))
	}
	return fmt.Sprintf("%s\u2026 (%d chars)", s[:4], len(s))
}

// scan returns the body with secrets replaced by deterministic placeholders
// and the list of hits. Same secret → same placeholder every turn, which keeps
// Anthropic prompt caching intact and the model's view consistent.
func (s *scanner) scan(body []byte) ([]byte, []hit) {
	// ponytail: scans the raw JSON text rather than walking the tree. Secrets
	// never contain quotes/backslashes so replacement keeps the JSON valid and
	// preserves byte order. Revisit if a rule ever matches across JSON escapes.
	var hits []hit
	redact := func(ruleID, secret string) {
		hits = append(hits, hit{ruleID, secret})
		sum := sha256.Sum256([]byte(secret))
		placeholder := fmt.Sprintf("[REDACTED:%s:%s]", ruleID, hex.EncodeToString(sum[:4]))
		body = bytes.ReplaceAll(body, []byte(secret), []byte(placeholder))
	}
	for _, lit := range s.literals {
		if bytes.Contains(body, lit) {
			redact("literal", string(lit))
		}
	}
	seen := map[string]bool{}
	for _, f := range s.det.DetectString(string(body)) {
		if f.Secret == "" || seen[f.Secret] {
			continue
		}
		seen[f.Secret] = true
		redact(f.RuleID, f.Secret)
	}
	return body, hits
}

// newDetector loads a gitleaks-format TOML config, or the embedded default
// rule set when path is empty. Configs can `[extend] useDefault = true` to add
// rules on top of the defaults.
func newDetector(path string) (*detect.Detector, error) {
	if path == "" {
		return detect.NewDetectorDefaultConfig()
	}
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("toml")
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	var vc glconfig.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return nil, err
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}
	return detect.NewDetector(cfg), nil
}

// loadLiterals reads exact secret strings, one per line. Blank lines and
// #-comments are skipped.
func loadLiterals(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, []byte(line))
	}
	return out, nil
}

// keyFileLiterals reads well-known credential files (private keys in ~/.ssh,
// ~/.aws/credentials) and returns every long line as a literal. A PEM body
// line is one literal; a `name = value` line gives its value. The proxy scans
// the raw JSON body, so each key line still matches when the file is pasted.
// Nothing is written to disk: the keys stay in memory.
func keyFileLiterals(home string) [][]byte {
	// ponytail: fixed path list; add a flag when someone needs more locations.
	paths := []string{filepath.Join(home, ".aws", "credentials")}
	ssh, _ := filepath.Glob(filepath.Join(home, ".ssh", "*"))
	for _, p := range ssh {
		b := filepath.Base(p)
		if strings.HasSuffix(b, ".pub") || b == "config" || b == "authorized_keys" || strings.HasPrefix(b, "known_hosts") {
			continue
		}
		paths = append(paths, p)
	}
	var out [][]byte
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			if v := f[len(f)-1]; len(v) >= 20 {
				out = append(out, []byte(v))
			}
		}
	}
	return out
}

func newProxy(upstream *url.URL, s *scanner, block bool) http.Handler {
	rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(upstream)
		pr.Out.Host = upstream.Host
	}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			rp.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Content-Encoding") != "" {
			reject(w, "hygienics: cannot scan encoded request body")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			reject(w, "hygienics: "+err.Error())
			return
		}
		clean, hits := s.scan(body)
		for _, h := range hits {
			log.Printf("%s %s: secret detected (%s %s)", r.Method, r.URL.Path, h.RuleID, mask(h.Secret))
		}
		if block && len(hits) > 0 {
			reject(w, fmt.Sprintf("hygienics: request blocked, %d secret(s) detected (%s %s)", len(hits), hits[0].RuleID, mask(hits[0].Secret)))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(clean))
		r.ContentLength = int64(len(clean))
		rp.ServeHTTP(w, r)
	})
}

// rollingLog appends to a file and keeps only the newest limit lines.
type rollingLog struct {
	path  string
	limit int
	f     *os.File // opened O_APPEND: writes always land at EOF, even after a trim rewrite
	count int
}

func openRollingLog(path string, limit int) (*rollingLog, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rollingLog{path: path, limit: limit, f: f, count: bytes.Count(data, []byte("\n"))}, nil
}

func (r *rollingLog) Write(p []byte) (int, error) {
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
func (r *rollingLog) trim() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.path, lastLines(data, r.limit), 0o600); err != nil {
		return err
	}
	r.count = r.limit
	return nil
}

// lastLines returns the last n lines of data.
func lastLines(data []byte, n int) []byte {
	for extra := bytes.Count(data, []byte("\n")) - n; extra > 0; extra-- {
		data = data[bytes.IndexByte(data, '\n')+1:]
	}
	return data
}

// reject answers in the Anthropic error format so Claude Code shows the message.
func reject(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	fmt.Fprintf(w, `{"type":"error","error":{"type":"invalid_request_error","message":%q}}`, msg)
}

// completionScript is a bash-style completion function. It also operates in
// zsh after `bashcompinit`.
const completionScript = `_hygienics() {
    local cur="${COMP_WORDS[COMP_CWORD]}" prev="${COMP_WORDS[COMP_CWORD-1]}"
    case "$prev" in
        -mode) COMPREPLY=($(compgen -W "redact block" -- "$cur")); return;;
        -secrets|-config|-log) COMPREPLY=($(compgen -f -- "$cur")); return;;
    esac
    if [[ ${COMP_WORDS[1]} == secret ]]; then
        COMPREPLY=($(compgen -W "add remove list path -secrets" -- "$cur"))
    elif [[ ${COMP_WORDS[1]} == setup ]]; then
        COMPREPLY=($(compgen -W "-secrets -entropy" -- "$cur"))
    else
        COMPREPLY=($(compgen -W "secret setup logs completion help -listen -upstream -mode -config -secrets -log -log-lines" -- "$cur"))
    fi
}
complete -F _hygienics hygienics
`

// logsCmd prints the rolling log file written by the proxy.
func logsCmd(args []string) error {
	home, _ := os.UserHomeDir()
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	path := fs.String("log", filepath.Join(home, ".config", "hygienics", "hygienics.log"), "log file to read")
	n := fs.Int("n", 0, "print only the last N lines (0 = all)")
	fs.Parse(args)
	data, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	if *n > 0 {
		data = lastLines(data, *n)
	}
	_, err = os.Stdout.Write(data)
	return err
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "completion" {
		fmt.Print(completionScript)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		if err := setupCmd(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "secret" {
		if err := secretCmd(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "logs" {
		if err := logsCmd(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	home, _ := os.UserHomeDir()
	defaultSecrets := filepath.Join(home, ".config", "hygienics", "secrets")
	defaultLog := filepath.Join(home, ".config", "hygienics", "hygienics.log")
	listen := flag.String("listen", "127.0.0.1:8787", "address to listen on")
	up := flag.String("upstream", "https://api.anthropic.com", "upstream API base URL")
	mode := flag.String("mode", "redact", "redact | block")
	rules := flag.String("config", "", "gitleaks-format TOML rule config (default: embedded gitleaks rules)")
	secrets := flag.String("secrets", defaultSecrets, "file with exact secret strings, one per line")
	logFile := flag.String("log", defaultLog, "also append log output to this file (rolling); empty disables")
	logLines := flag.Int("log-lines", 10000, "maximum number of lines kept in the log file")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), `hygienics `+version+`

Usage:
  hygienics [options]              start the proxy
  hygienics secret add             add a secret to the secrets file
  hygienics secret remove          remove a secret from the secrets file
  hygienics secret list            show each secret in a masked form
  hygienics secret path            show the path of the secrets file
  hygienics setup                  scan the environment, add found secrets to the secrets file
  hygienics logs [-n N]            print the log of the running or last proxy (last N lines)
  hygienics completion             print the shell completion script
  hygienics help                   show this help

The add and remove commands show the prompt "enter secret".
Type the secret, then push Enter.
The secret does not go into the shell history.

Options:
`)
		flag.PrintDefaults()
	}
	if len(os.Args) > 1 && os.Args[1] == "help" {
		flag.Usage()
		return
	}
	flag.Parse()
	if *logFile != "" {
		os.MkdirAll(filepath.Dir(*logFile), 0o700)
		rl, err := openRollingLog(*logFile, *logLines)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(io.MultiWriter(os.Stderr, rl))
	}
	upstream, err := url.Parse(*up)
	if err != nil {
		log.Fatal(err)
	}
	det, err := newDetector(*rules)
	if err != nil {
		log.Fatal(err)
	}
	s := &scanner{det: det}
	if lits, err := loadLiterals(*secrets); err == nil {
		s.literals = lits
		log.Printf("loaded %d literal secret(s) from %s", len(lits), *secrets)
	} else if !os.IsNotExist(err) || *secrets != defaultSecrets {
		log.Fatal(err) // explicit -secrets path must exist; missing default is fine
	}
	if keys := keyFileLiterals(home); len(keys) > 0 {
		s.literals = append(s.literals, keys...)
		log.Printf("loaded %d line(s) from key files in ~/.ssh and ~/.aws", len(keys))
	}
	// ponytail: the port bind is the "already running" check; no pidfile needed.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v — is hygienics already running?", *listen, err)
	}
	log.Printf("hygienics %s listening on %s → %s (mode=%s)", version, *listen, upstream, *mode)
	log.Fatal(http.Serve(ln, newProxy(upstream, s, *mode == "block")))
}

// secretCmd manages the literal-secrets file:
//
//	hygienics secret [-secrets file] add|remove|list|path
//
// add/remove prompt for the secret on stdin so it stays out of shell history;
// an argument is refused.
func secretCmd(args []string) error {
	home, _ := os.UserHomeDir()
	fs := flag.NewFlagSet("secret", flag.ExitOnError)
	path := fs.String("secrets", filepath.Join(home, ".config", "hygienics", "secrets"), "file with exact secret strings, one per line")
	fs.Parse(args)
	verb, value := fs.Arg(0), ""
	if verb == "add" || verb == "remove" {
		if fs.NArg() > 1 {
			return fmt.Errorf("do not give the secret as an argument; the shell history keeps arguments")
		}
		fmt.Fprint(os.Stderr, "enter secret: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if value = strings.TrimSpace(line); value == "" {
			return fmt.Errorf("empty secret")
		}
	}
	data, err := os.ReadFile(*path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	switch verb {
	case "add":
		for _, l := range lines {
			if strings.TrimSpace(l) == value {
				return nil // already listed
			}
		}
		if err := os.MkdirAll(filepath.Dir(*path), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(*path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(value + "\n")
		return err
	case "remove":
		var kept []string
		for _, l := range lines {
			if strings.TrimSpace(l) != value {
				kept = append(kept, l)
			}
		}
		if len(kept) == len(lines) {
			return fmt.Errorf("secret not found in %s", *path)
		}
		out := strings.Join(kept, "\n")
		if out != "" {
			out += "\n"
		}
		return os.WriteFile(*path, []byte(out), 0o600)
	case "path":
		fmt.Println(*path)
		return nil
	case "list":
		// ponytail: masked output; this terminal may itself feed an AI session.
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			fmt.Printf("%s\u2026 (%d chars)\n", l[:min(4, len(l))], len(l))
		}
		return nil
	default:
		return fmt.Errorf("usage: hygienics secret [-secrets file] add|remove|list|path")
	}
}

// boring lists env vars that must never count as secrets even if a rule fires.
var boring = map[string]bool{
	"PATH": true, "HOME": true, "PWD": true, "OLDPWD": true, "SHELL": true,
	"SHLVL": true, "TERM": true, "USER": true, "LOGNAME": true, "TMPDIR": true,
	"LANG": true, "EDITOR": true, "PAGER": true,
}

type envHit struct{ Name, Rule, Secret string }

// shannon returns the Shannon entropy of s in bits per byte.
func shannon(s string) float64 {
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n, h := float64(len(s)), 0.0
	for _, c := range freq {
		if c > 0 {
			p := c / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// envSecrets runs the gitleaks rules over each NAME=value pair. The variable
// name gives the detector context (TOKEN, PASSWORD, ...) that request bodies
// lack later — that context is why setup harvests the values as literals.
func envSecrets(environ []string, det *detect.Detector, entropy float64) []envHit {
	var out []envHit
	seen := map[string]bool{}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		// ponytail: "/" prefix skips paths (no secret starts with a slash);
		// <8 chars skips values whose redaction would corrupt normal text.
		if boring[name] || strings.HasPrefix(name, "LC_") ||
			len(value) < 8 || strings.HasPrefix(value, "/") {
			continue
		}
		findings := det.DetectString(name + "=" + value)
		for _, f := range findings {
			if len(f.Secret) < 8 || !strings.Contains(value, f.Secret) || seen[f.Secret] {
				continue
			}
			seen[f.Secret] = true
			out = append(out, envHit{name, f.RuleID, f.Secret})
		}
		// ponytail: recall-over-precision fallback — a high-entropy value
		// counts as a secret even without a rule match or a name keyword.
		// 3.3 bits/byte needs ~12 mostly-unique chars; the space skip drops
		// natural-language values. Raise -entropy if the output is too noisy.
		if len(findings) == 0 && entropy > 0 && !seen[value] &&
			!strings.ContainsAny(value, " \t") && shannon(value) >= entropy {
			seen[value] = true
			out = append(out, envHit{name, "high-entropy", value})
		}
	}
	return out
}

// setupCmd scans the process environment for secrets and appends them to the
// literals file:
//
//	hygienics setup [-secrets file]
func setupCmd(args []string) error {
	home, _ := os.UserHomeDir()
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	path := fs.String("secrets", filepath.Join(home, ".config", "hygienics", "secrets"), "file with exact secret strings, one per line")
	entropy := fs.Float64("entropy", 3.3, "entropy threshold in bits per byte for the fallback check; 0 turns the check off")
	fs.Parse(args)
	det, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return err
	}
	found := envSecrets(os.Environ(), det, *entropy)
	if len(found) == 0 {
		fmt.Println("no secrets found in the environment")
		return nil
	}
	existing := map[string]bool{}
	if lits, err := loadLiterals(*path); err == nil {
		for _, l := range lits {
			existing[string(l)] = true
		}
	}
	if err := os.MkdirAll(filepath.Dir(*path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(*path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	added := 0
	for _, c := range found {
		state := "added"
		if existing[c.Secret] {
			state = "already listed"
		} else if _, err := f.WriteString(c.Secret + "\n"); err != nil {
			return err
		} else {
			existing[c.Secret] = true
			added++
		}
		// masked output only; this terminal may itself feed an AI session
		fmt.Printf("%-24s %s… (%d chars, %s) %s\n", c.Name, c.Secret[:min(4, len(c.Secret))], len(c.Secret), c.Rule, state)
	}
	fmt.Printf("%d secret(s) added to %s\n", added, *path)
	fmt.Println("examine the list; remove a wrong entry with: hygienics secret remove")
	return nil
}
