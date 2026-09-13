// Package scan detects secrets in bytes, files and the environment.
package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	glconfig "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// Scanner finds secrets in request bodies: gitleaks rules plus exact literals.
type Scanner struct {
	Det      *detect.Detector
	Literals [][]byte // exact strings that must never leave the machine
}

// Hit is one detected secret.
type Hit struct{ RuleID, Secret string }

// Mask gives a safe preview of a secret: the first 4 characters and the
// length. Enough to identify it, never enough to leak it.
func Mask(s string) string {
	if len(s) <= 8 {
		return fmt.Sprintf("(%d chars)", len(s))
	}
	return fmt.Sprintf("%s\u2026 (%d chars)", s[:4], len(s))
}

// Scan returns the body with secrets replaced by deterministic placeholders
// and the list of hits. Same secret → same placeholder every turn, which keeps
// Anthropic prompt caching intact and the model's view consistent.
func (s *Scanner) Scan(body []byte) ([]byte, []Hit) {
	// ponytail: scans the raw JSON text rather than walking the tree. Secrets
	// never contain quotes/backslashes so replacement keeps the JSON valid and
	// preserves byte order. Revisit if a rule ever matches across JSON escapes.
	var hits []Hit
	redact := func(ruleID, secret string) {
		hits = append(hits, Hit{ruleID, secret})
		sum := sha256.Sum256([]byte(secret))
		placeholder := fmt.Sprintf("[REDACTED:%s:%s]", ruleID, hex.EncodeToString(sum[:4]))
		body = bytes.ReplaceAll(body, []byte(secret), []byte(placeholder))
	}
	for _, lit := range s.Literals {
		if bytes.Contains(body, lit) {
			redact("literal", string(lit))
		}
	}
	seen := map[string]bool{}
	for _, f := range s.Det.DetectString(string(body)) {
		if f.Secret == "" || seen[f.Secret] {
			continue
		}
		seen[f.Secret] = true
		redact(f.RuleID, f.Secret)
	}
	return body, hits
}

// NewDetector loads a gitleaks-format TOML config, or the embedded default
// rule set when path is empty. Configs can `[extend] useDefault = true` to add
// rules on top of the defaults.
func NewDetector(path string) (*detect.Detector, error) {
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

// LoadLiterals reads exact secret strings, one per line. Blank lines and
// #-comments are skipped.
func LoadLiterals(path string) ([][]byte, error) {
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

// KeyFileLiterals reads well-known credential files (private keys in ~/.ssh,
// ~/.aws/credentials, ~/.netrc, ~/.npmrc, ...) and returns every long line as a literal. A PEM body
// line is one literal; a `name = value` line gives its value. The proxy scans
// the raw JSON body, so each key line still matches when the file is pasted.
// Nothing is written to disk: the keys stay in memory.
func KeyFileLiterals(home string) [][]byte {
	// ponytail: fixed path list; add a flag when someone needs more locations.
	var paths []string
	for _, rel := range []string{
		".aws/credentials", ".netrc", ".git-credentials", ".config/git/credentials",
		".npmrc", ".pypirc", ".docker/config.json", ".kube/config",
		".config/gh/hosts.yml", ".fly/config.yml",
		".config/gcloud/application_default_credentials.json",
		".terraform.d/credentials.tfrc.json", ".cargo/credentials.toml", ".vault-token",
	} {
		paths = append(paths, filepath.Join(home, filepath.FromSlash(rel)))
	}
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
			// Trim JSON/TOML/YAML decoration: `"value",` → value.
			if v := strings.Trim(f[len(f)-1], `"',{}[]`); len(v) >= 20 {
				out = append(out, []byte(v))
			}
		}
	}
	return out
}

// boring lists env vars that must never count as secrets even if a rule fires.
var boring = map[string]bool{
	"PATH": true, "HOME": true, "PWD": true, "OLDPWD": true, "SHELL": true,
	"SHLVL": true, "TERM": true, "USER": true, "LOGNAME": true, "TMPDIR": true,
	"LANG": true, "EDITOR": true, "PAGER": true,
}

// EnvHit is a secret found in an environment variable.
type EnvHit struct{ Name, Rule, Secret string }

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

// EnvSecrets runs the gitleaks rules over each NAME=value pair. The variable
// name gives the detector context (TOKEN, PASSWORD, ...) that request bodies
// lack later — that context is why setup harvests the values as Literals.
func EnvSecrets(environ []string, det *detect.Detector, entropy float64) []EnvHit {
	var out []EnvHit
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
			out = append(out, EnvHit{name, f.RuleID, f.Secret})
		}
		// ponytail: recall-over-precision fallback — a high-entropy value
		// counts as a secret even without a rule match or a name keyword.
		// 3.3 bits/byte needs ~12 mostly-unique chars; the space skip drops
		// natural-language values. Raise -entropy if the output is too noisy.
		if len(findings) == 0 && entropy > 0 && !seen[value] &&
			!strings.ContainsAny(value, " \t") && shannon(value) >= entropy {
			seen[value] = true
			out = append(out, EnvHit{name, "high-entropy", value})
		}
	}
	return out
}
