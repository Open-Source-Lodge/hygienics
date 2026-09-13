// Package proxy is the reverse proxy that redacts or blocks requests with secrets.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"hygienics/internal/scan"
)

// New returns a handler that scans request bodies and forwards them to upstream.
func New(upstream *url.URL, s *scan.Scanner, block bool) http.Handler {
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
			reject(w, "hygienics: cannot Scan encoded request body")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			reject(w, "hygienics: "+err.Error())
			return
		}
		clean, hits := s.Scan(body)
		for _, h := range hits {
			log.Printf("%s %s: secret detected (%s %s)", r.Method, r.URL.Path, h.RuleID, scan.Mask(h.Secret))
		}
		if block && len(hits) > 0 {
			reject(w, fmt.Sprintf("hygienics: request blocked, %d secret(s) detected (%s %s)", len(hits), hits[0].RuleID, scan.Mask(hits[0].Secret)))
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
