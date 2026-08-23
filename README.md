# hygenics

Local proxy that scans everything Claude Code sends to Anthropic for secrets, before it leaves your machine. Redacts them (default) or blocks the request.

```sh
go build -o hygenics .
./hygenics                          # 127.0.0.1:8787 → api.anthropic.com, mode=redact
./hygenics -mode block

export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

## Custom secrets

**Exact strings** — the easy way. One secret per line in `~/.config/hygenics/secrets`
(or pass `-secrets path`); `#` comments and blank lines are ignored:

```
# never send these
abc123
my-internal-db-password
```

Any request containing one of these is redacted/blocked, no regex needed.

**Pattern rules** — pass `-config rules.toml` in gitleaks format, extending the defaults:

```toml
[extend]
useDefault = true

[[rules]]
id = "acme-token"
description = "ACME internal token"
regex = '''acme-[a-z0-9]{12}'''
```

## Detection

Built-in rules come from [gitleaks](https://github.com/gitleaks/gitleaks)' default set (~220 rules, entropy-aware). Redacted values become `[REDACTED:<rule>:<hash>]` — deterministic, so prompt caching keeps working across turns.

See `RESEARCH.md` for why a proxy and not hooks.
