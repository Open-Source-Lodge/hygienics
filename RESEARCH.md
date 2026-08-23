# Research: how to find secrets in the Claude Code output traffic

Date: 2026-08-23

## Points where we can examine the traffic

| Layer | Data that the layer sees | Changes possible | Result |
|---|---|---|---|
| Hooks `UserPromptSubmit` / `PreToolUse` | user prompt text, tool inputs | yes (`updatedInput`), or stop | partial — the hooks do not see tool results, `@file` content, CLAUDE.md, compaction data, or subagent traffic |
| Hook `PostToolUse` | tool results | no (read only) | the hook cannot change the data that the Read or Bash tools return |
| `ANTHROPIC_BASE_URL` → local reverse proxy | all bytes of each Messages API request (system, messages, tools) | yes, the proxy is our process | **the only point that sees all the data** |
| `HTTPS_PROXY` + MITM CA | the same data | yes | necessary only for tools that ignore the base URL (Cursor, Copilot, Codex) — not necessary for Claude Code |
| `sandbox.credentials`, `permissions.deny` | file and environment reads by tools | stop or mask | a good addition; recommend this in the documentation |
| Anthropic Inference Hooks (Enterprise) | transcript, on the server | permit or deny only | not applicable |

Facts from the documentation (code.claude.com/docs/en/{hooks,network-config,llm-gateway-protocol}.md):
- `ANTHROPIC_BASE_URL` operates with an API key and with claude.ai OAuth login.
- Each request is standard `POST /v1/messages` JSON. Each response is an SSE stream with `ping` messages. The proxy must send the `ping` messages through. The idle timeout is 300 seconds.
- Telemetry and feature-flag traffic also goes to api.anthropic.com. Set `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` to stop this traffic.
- Issue anthropics/claude-code#29434 (closed, not planned): hooks cannot change all the data. Thus each applicable known tool is a proxy.

**Decision: make a local reverse proxy and set `ANTHROPIC_BASE_URL` to it.** Hooks are a possible addition for early warnings.

## Design constraints

- Claude Code sends the full conversation in each turn (100 KB to 1 MB). The full gitleaks rule set scans approximately 5 MB/s. This is approximately 20 ms for each 100 KB. This speed is sufficient. A cache can decrease the scan time. Calculate a hash for each content block. Keep the scan result for each hash. Then scan only the new blocks.
- The replacement of a secret must always be the same. If the replacement changes, the Anthropic prompt cache stops and the model becomes confused.
- Change only JSON string values. Walk the JSON tree. Tool results can contain JSON in strings. Scan the decoded strings.
- Also scan the `system` and `tools` blocks. The CLAUDE.md content goes with each turn.
- Block mode: send an error response to Claude Code with a message that a person can read.
- The response stream goes through without changes. Version 1 scans only the output traffic.

## Related tools

- WangYihang/LLM-Redactor — Go, contains gitleaks as a library, uses HTTPS_PROXY. 11 stars.
- larsderidder/contextio — TypeScript, no dependencies, `ANTHROPIC_BASE_URL` proxy, reversible replacement, includes SSE changes. 30 stars, MIT.
- GuthL/KeyClaw — Rust MITM, own detectors and entropy checks. 6 stars.
- paroque28/claude-code-redact — Python, proxy mode or hook mode. 3 stars.
- coo-quack/sensitive-canary, l-mb/claude-code-redaction-hooks — hook tools. The second README gives a warning: hooks cannot control all the output traffic.
- Commercial tools (in the cloud, not local): Nightfall, Pangea, Cloudflare AI Gateway DLP, Portkey, LiteLLM (the secret detection is only in the enterprise version).

No tool is local and mature. The area is open.

## Rule database

**Use the gitleaks file `config/gitleaks.toml`.** The file has 222 rules, an MIT license, and RE2 syntax. RE2 syntax has no lookaround. Thus Go, Rust, and Hyperscan can read the rules. JavaScript is possible with small changes. The `keywords` field gives a fast first filter. 130 rules have entropy limits. All languages can read the TOML format.
- betterleaks: a new fork from the first gitleaks author. The same format with additions. Monitor this project.
- secrets-patterns-db: 1,610 YAML patterns, CC-BY-SA license, not maintained, many false alerts. Use only the `confidence: high` patterns to fill gaps.
- trufflehog: AGPL license. The detectors are Go code. Do not link this library.
- detect-secrets (27 plugins, Python) and secretlint (approximately 33 rules, TypeScript): small sets, not portable.

## Language options

| | Proxy | Engine | Distribution | Notes |
|---|---|---|---|---|
| **Go** | `httputil.ReverseProxy` from the standard library, automatic SSE flush | use gitleaks as a library (`detect.NewDetector`) | one static binary | the shortest path; LLM-Redactor shows that this operates |
| **Rust** | axum + hyper | `regex::RegexSet` + `aho-corasick`, read the gitleaks TOML | one binary | the fastest scan; more code is necessary (a new copy of the gitleaks functions) |
| **TypeScript** | undici fetch + stream pipe, no dependencies | read the gitleaks TOML (small regex differences) or `@secretlint/core` | npm / npx, the same system as the Claude Code hooks and plugins | the easiest installation for Claude Code users (`npx`), the slowest scan |
| **Python** | starlette + httpx, or a mitmproxy addon | detect-secrets / llm-guard | pip; a large runtime | the best option for MITM in the future (mitmproxy), the smallest rule set |

## Decision

**Go.** A reverse proxy on the standard library, gitleaks as a library, one binary.
