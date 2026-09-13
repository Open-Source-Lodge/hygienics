# hygienics

Local reverse proxy that scans Claude Code's outbound Messages API traffic for secrets, then redacts (default) or blocks. Go, single binary, gitleaks embedded as a library.

## Commands

- `make build` / `make test` / `make start` (redact) / `make start-block`
- Use: `export ANTHROPIC_BASE_URL=http://127.0.0.1:8787` then `claude`

## Architecture decisions (see RESEARCH.md for sources)

- **Proxy, not hooks.** Claude Code hooks cannot rewrite tool results, `@file` content, CLAUDE.md, compaction, or subagent traffic (anthropics/claude-code#29434). Only a proxy behind `ANTHROPIC_BASE_URL` sees everything. It works with both API keys and claude.ai OAuth.
- **Deterministic placeholders.** Same secret must always become the same `[REDACTED:<rule>:<hash>]`, or Anthropic's prompt cache breaks and the model gets confused. Never make redaction random or session-scoped.
- **Raw-body scanning.** We scan/replace on the raw JSON bytes, not a parsed tree (see `ponytail:` comment in internal/scan/scan.go). Valid because secrets don't contain quotes/backslashes.
- **Rules:** gitleaks default TOML (MIT). Do not link trufflehog (AGPL). Custom: `-config` (gitleaks-format TOML) and `-secrets` (literal strings file, default `~/.config/hygienics/secrets`).
- SSE responses pass through untouched; forward `ping` events (300 s idle timeout).

## Critical: no secret-shaped literals in this repo

Development sessions on this repo may themselves run through a redacting proxy. A secret-shaped literal (fake or real) in source/tests gets silently redacted from the AI's context and corrupts the file when it round-trips — this actually happened to the test file. Always build test tokens at runtime (see `key` in internal/scan/scan_test.go). When editing near them, use scripted replacements, not copy-paste.

## Style

- Documentation follows ASD-STE100 Simplified Technical English (short sentences, active voice, one instruction per sentence).
- Language decisions and similar big choices: ask the user with alternatives, don't decide unilaterally.

## History note

The project was `~/github/hygenics` (typo) and moved to `~/github/hygienics` on 2026-08-23. The old directory may still exist as a stale duplicate; this repo has the canonical history.
