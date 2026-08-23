// hygenics: local reverse proxy for Claude Code that scans every outbound
// Messages API request for secrets before it leaves the machine.
//
//	export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
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

type scanner struct {
	det      *detect.Detector
	literals [][]byte // exact strings that must never leave the machine
}

type hit struct{ RuleID, Secret string }

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
			reject(w, "hygenics: cannot scan encoded request body")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			reject(w, "hygenics: "+err.Error())
			return
		}
		clean, hits := s.scan(body)
		for _, h := range hits {
			log.Printf("%s %s: secret detected (%s)", r.Method, r.URL.Path, h.RuleID)
		}
		if block && len(hits) > 0 {
			reject(w, fmt.Sprintf("hygenics: request blocked, %d secret(s) detected (%s)", len(hits), hits[0].RuleID))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(clean))
		r.ContentLength = int64(len(clean))
		rp.ServeHTTP(w, r)
	})
}

// reject answers in the Anthropic error format so Claude Code shows the message.
func reject(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	fmt.Fprintf(w, `{"type":"error","error":{"type":"invalid_request_error","message":%q}}`, msg)
}

func main() {
	home, _ := os.UserHomeDir()
	defaultSecrets := filepath.Join(home, ".config", "hygenics", "secrets")
	listen := flag.String("listen", "127.0.0.1:8787", "address to listen on")
	up := flag.String("upstream", "https://api.anthropic.com", "upstream API base URL")
	mode := flag.String("mode", "redact", "redact | block")
	rules := flag.String("config", "", "gitleaks-format TOML rule config (default: embedded gitleaks rules)")
	secrets := flag.String("secrets", defaultSecrets, "file with exact secret strings, one per line")
	flag.Parse()
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
	log.Printf("hygenics listening on %s → %s (mode=%s)", *listen, upstream, *mode)
	log.Fatal(http.ListenAndServe(*listen, newProxy(upstream, s, *mode == "block")))
}
