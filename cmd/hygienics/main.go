// hygienics: local reverse proxy for Claude Code that scans every outbound
// Messages API request for secrets before it leaves the machine.
//
//	export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/detect"

	"hygienics/internal/logfile"
	"hygienics/internal/proxy"
	"hygienics/internal/scan"
)

// The release workflow sets version with ldflags.
var version = "dev"

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
		data = logfile.LastLines(data, *n)
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
		rl, err := logfile.Open(*logFile, *logLines)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(io.MultiWriter(os.Stderr, rl))
	}
	upstream, err := url.Parse(*up)
	if err != nil {
		log.Fatal(err)
	}
	det, err := scan.NewDetector(*rules)
	if err != nil {
		log.Fatal(err)
	}
	s := &scan.Scanner{Det: det}
	if lits, err := scan.LoadLiterals(*secrets); err == nil {
		s.Literals = lits
		log.Printf("loaded %d literal secret(s) from %s", len(lits), *secrets)
	} else if !os.IsNotExist(err) || *secrets != defaultSecrets {
		log.Fatal(err) // explicit -secrets path must exist; missing default is fine
	}
	if keys := scan.KeyFileLiterals(home); len(keys) > 0 {
		s.Literals = append(s.Literals, keys...)
		log.Printf("loaded %d line(s) from key and credential files in home", len(keys))
	}
	// ponytail: the port bind is the "already running" check; no pidfile needed.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v — is hygienics already running?", *listen, err)
	}
	log.Printf("hygienics %s listening on %s → %s (mode=%s)", version, *listen, upstream, *mode)
	log.Fatal(http.Serve(ln, proxy.New(upstream, s, *mode == "block")))
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

// setupCmd scans the process environment for secrets and appends them to the
// Literals file:
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
	found := scan.EnvSecrets(os.Environ(), det, *entropy)
	if len(found) == 0 {
		fmt.Println("no secrets found in the environment")
		return nil
	}
	existing := map[string]bool{}
	if lits, err := scan.LoadLiterals(*path); err == nil {
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
