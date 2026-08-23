# Research: secrets scanning for Claude Code egress

Date: 2026-08-23

## Where can we intercept?

| Layer | Sees | Can modify | Verdict |
|---|---|---|---|
| Hooks `UserPromptSubmit` / `PreToolUse` | user prompt text, tool *inputs* | yes (`updatedInput`) or block | partial — misses tool results, `@file` mentions, CLAUDE.md, compaction, subagents |
| Hooks `PostToolUse` | tool results | **no** (read-only) | can't redact what Read/Bash returns |
| `ANTHROPIC_BASE_URL` → local reverse proxy | **every byte** of every Messages API request (system, messages, tools) | yes, it's our process | **the only complete interception point** |
| `HTTPS_PROXY` + MITM CA | same as above | yes | needed only for tools that ignore base URL (Cursor/Copilot/Codex) — not for Claude Code |
| `sandbox.credentials`, `permissions.deny` | file/env reads by tools | block/mask | complementary, built-in, recommend in docs |
| Anthropic Inference Hooks (Enterprise) | transcript, server-side | allow/deny only | out of scope |

Facts verified from docs (code.claude.com/docs/en/{hooks,network-config,llm-gateway-protocol}.md):
- `ANTHROPIC_BASE_URL` works with API key **and** claude.ai OAuth login.
- Requests are standard `POST /v1/messages` JSON; responses are SSE with `ping` keep-alives that must be forwarded (300 s idle timeout).
- Non-model traffic (telemetry, feature flags) still hits api.anthropic.com; `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` stops it.
- anthropics/claude-code#29434 (closed, not planned): no rewrite channel for everything via hooks — which is why every serious prior-art project is a proxy.

**Decision: build a local reverse proxy behind `ANTHROPIC_BASE_URL`.** Hooks optional later as a cheap early warning.

## Design constraints learned

- Claude Code resends the whole conversation every turn (100 KB–1 MB). gitleaks full rule set ≈ 5 MB/s → ~20 ms/100 KB, ~200 ms/MB. Fine, but cache: hash each content block, memoize scan results; only new blocks get scanned.
- Redaction must be **deterministic** (same secret → same placeholder, persisted per session) or it breaks Anthropic prompt caching and confuses the model.
- Redact only JSON string values (walk the tree); tool results often contain JSON-inside-strings — scan decoded strings.
- Scan `system` and `tools` blocks too (CLAUDE.md contents ride along every turn).
- Block mode = return an error response to Claude Code with a human-readable message.
- Streaming responses pass through untouched (we scan outbound only, v1).

## Prior art (closest first)

- WangYihang/LLM-Redactor — Go, embeds gitleaks as library, HTTPS_PROXY based. 11★.
- larsderidder/contextio — TS, zero deps, `ANTHROPIC_BASE_URL` proxy, reversible redaction incl. SSE rewrite. 30★, MIT.
- GuthL/KeyClaw — Rust MITM, own detectors + entropy. 6★.
- paroque28/claude-code-redact — Python, proxy or hook mode. 3★.
- coo-quack/sensitive-canary, l-mb/claude-code-redaction-hooks — hook-based; the latter's README warns hooks can't cover egress.
- Commercial (cloud-side, not local): Nightfall, Pangea, Cloudflare AI Gateway DLP, Portkey, LiteLLM (secret detection is enterprise-only).

Nothing mature and local exists. Space is open.

## Rule database

**Use gitleaks `config/gitleaks.toml`** — 222 rules, MIT, RE2 syntax (no lookaround → loads into Go/Rust/Hyperscan; JS needs minor care), `keywords` prefilter for Aho-Corasick, 130 rules carry entropy thresholds. Parseable from any language.
- betterleaks: newer fork by gitleaks' original author, same format + extras. Track it.
- secrets-patterns-db: 1,610 YAML regexes, CC-BY-SA, unmaintained, noisy — use only `confidence: high` for gap-filling.
- trufflehog: AGPL, detectors are Go code → don't link.
- detect-secrets (27 plugins, Python), secretlint (~33 rules, TS): smaller, not portable.

## Language options

| | Proxy | Engine | Distribution | Notes |
|---|---|---|---|---|
| **Go** | stdlib `httputil.ReverseProxy`, auto-flushes SSE | link gitleaks directly (`detect.NewDetector`) | single static binary | shortest path; LLM-Redactor proves it |
| **Rust** | axum + hyper | `regex::RegexSet` + `aho-corasick`, parse gitleaks TOML | single binary | fastest scan; more code to write (reimplement gitleaks semantics) |
| **TypeScript** | undici fetch + stream pipe, zero deps | parse gitleaks TOML (regex dialect caveats) or `@secretlint/core` | npm / npx, same ecosystem as Claude Code hooks & plugins | easiest install for Claude Code users (`npx`), slowest scan |
| **Python** | starlette + httpx, or mitmproxy addon | detect-secrets / llm-guard | pip; heavier runtime | best for MITM later (mitmproxy), weakest rule DB |

## Decision

**Go.** Reverse proxy on stdlib, gitleaks linked as a library, single binary.
