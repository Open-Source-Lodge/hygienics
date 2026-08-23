# hygenics

Local proxy that scans everything Claude Code sends to Anthropic for secrets, before it leaves your machine. Redacts them (default) or blocks the request.

```sh
go build -o hygenics .
./hygenics                          # 127.0.0.1:8787 → api.anthropic.com, mode=redact
./hygenics -mode block

export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

Detection uses [gitleaks](https://github.com/gitleaks/gitleaks)' default rule set (~220 rules, entropy-aware). Redacted values become `[REDACTED:<rule>:<hash>]` — deterministic, so prompt caching keeps working across turns.

See `RESEARCH.md` for why a proxy and not hooks.
