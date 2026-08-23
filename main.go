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

	"github.com/zricethezav/gitleaks/v8/detect"
)

type scanner struct{ det *detect.Detector }

type hit struct{ RuleID, Secret string }

// scan returns the body with secrets replaced by deterministic placeholders
// and the list of hits. Same secret → same placeholder every turn, which keeps
// Anthropic prompt caching intact and the model's view consistent.
func (s *scanner) scan(body []byte) ([]byte, []hit) {
	// ponytail: scans the raw JSON text rather than walking the tree. Secrets
	// never contain quotes/backslashes so replacement keeps the JSON valid and
	// preserves byte order. Revisit if a rule ever matches across JSON escapes.
	var hits []hit
	seen := map[string]bool{}
	for _, f := range s.det.DetectString(string(body)) {
		if f.Secret == "" || seen[f.Secret] {
			continue
		}
		seen[f.Secret] = true
		hits = append(hits, hit{f.RuleID, f.Secret})
		sum := sha256.Sum256([]byte(f.Secret))
		placeholder := fmt.Sprintf("[REDACTED:%s:%s]", f.RuleID, hex.EncodeToString(sum[:4]))
		body = bytes.ReplaceAll(body, []byte(f.Secret), []byte(placeholder))
	}
	return body, hits
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
	listen := flag.String("listen", "127.0.0.1:8787", "address to listen on")
	up := flag.String("upstream", "https://api.anthropic.com", "upstream API base URL")
	mode := flag.String("mode", "redact", "redact | block")
	flag.Parse()
	upstream, err := url.Parse(*up)
	if err != nil {
		log.Fatal(err)
	}
	det, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("hygenics listening on %s → %s (mode=%s)", *listen, upstream, *mode)
	if err := http.ListenAndServe(*listen, newProxy(upstream, &scanner{det}, *mode == "block")); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
