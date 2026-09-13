<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="hygienics logo">
</p>

<h1 align="center">hygienics</h1>

<p align="center">
  A local proxy that removes secrets from Claude Code traffic before the traffic leaves your machine.
</p>

<p align="center">
  <a href="https://github.com/Open-Source-Lodge/hygienics/actions/workflows/test.yml"><img src="https://github.com/Open-Source-Lodge/hygienics/actions/workflows/test.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/Open-Source-Lodge/hygienics/releases/latest"><img src="https://img.shields.io/github/v/release/Open-Source-Lodge/hygienics" alt="release"></a>
</p>

---

Claude Code sends file content, shell output, and tool results to the Anthropic API. Some of that content can contain secrets. hygienics sits between Claude Code and the API. The proxy examines each request. If the proxy finds a secret, the proxy replaces the secret with a placeholder (default) or stops the request.

```
Claude Code ──▶ hygienics ──▶ api.anthropic.com
                   │
                   └─ <api key>  ──▶  [REDACTED:anthropic-api-key:3f9a1c2e]
```

## Features

- **Sees everything.** Claude Code hooks cannot change tool results, `@file` content, `CLAUDE.md`, compaction, or subagent traffic. A proxy behind `ANTHROPIC_BASE_URL` sees each request.
- **Approximately 220 rules.** The default rules come from [gitleaks](https://github.com/gitleaks/gitleaks). The rules include entropy checks.
- **Stable placeholders.** The same secret always becomes the same `[REDACTED:<rule>:<hash>]`. The prompt cache of Anthropic continues to operate. The model sees a consistent value.
- **Your own secrets.** Add exact strings and custom pattern rules. The proxy also loads the keys in `~/.ssh` and common credential files at start.
- **Works with API keys and claude.ai login.** The proxy does not touch authentication.
- **One binary.** No runtime dependencies. Builds for macOS, Linux, and Windows.

## Install

### Download a binary

Download the file for your platform from the [latest release](https://github.com/Open-Source-Lodge/hygienics/releases/latest). Compare the checksum with `checksums.txt`. Then make the file executable and put the file in your `PATH`:

```sh
chmod +x hygienics-darwin-arm64
mv hygienics-darwin-arm64 /usr/local/bin/hygienics
```

### Build from source

Requires Go 1.26 or later.

```sh
git clone https://github.com/Open-Source-Lodge/hygienics.git
cd hygienics
make build          # writes bin/hygienics
```

The command is in `cmd/hygienics`. Use `go build ./cmd/hygienics` to build without make. The packages in `internal/` hold the logic:

| package             | purpose                                                   |
| ------------------- | --------------------------------------------------------- |
| `internal/scan`     | finds secrets in request bodies, key files, and the environment |
| `internal/proxy`    | the HTTP handler that redacts or blocks a request         |
| `internal/logfile`  | the rotating log file                                     |

## Quick start

1. Start the proxy:
   ```sh
   hygienics                # listen on 127.0.0.1:8787, redact secrets
   hygienics -mode block    # stop each request that contains a secret
   ```
2. In a second terminal, point Claude Code at the proxy:
   ```sh
   export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
   claude
   ```
3. Review what the proxy caught:
   ```sh
   hygienics logs -n 50
   ```

Put the `export` line in your shell profile to make the setting permanent.

## Modes

| mode     | behavior                                                                                   |
| -------- | ------------------------------------------------------------------------------------------ |
| `redact` | Replace each secret with `[REDACTED:<rule>:<hash>]` and forward the request. Default.      |
| `block`  | Answer with HTTP 422 and an error message. Claude Code shows the message. Nothing leaves.   |

## Custom secrets

### Exact strings

Write each secret on one line in `~/.config/hygienics/secrets`. The proxy ignores blank lines and lines that start with `#`:

```
# do not send these
abc123
my-internal-db-password
```

The proxy removes or stops each request that contains one of these strings. A pattern is not necessary.

Use the `secret` command to change the file:

```sh
hygienics secret add       # add a secret
hygienics secret remove    # remove a secret
hygienics secret list      # show each secret in a masked form
hygienics secret path      # show the path of the secrets file
```

The `add` and `remove` commands show the prompt `enter secret`. Type the secret, then push Enter. The command does not accept the secret as an argument. Thus the secret does not go into the shell history.

Use `-secrets FILE` to select a different file, for both the proxy and the `secret` command.

### Automatic setup from the environment

The `setup` command examines the environment variables:

```sh
hygienics setup
```

The command applies the gitleaks rules to each `NAME=value` pair. The variable name gives context that a request body does not have. For example, the name `DB_PASSWORD` marks the value as a secret. The command adds each found value to the secrets file. The command ignores short values, paths, and common shell variables.

The command also makes an entropy check. A value with high entropy counts as a secret, also when no rule matches and the variable name is not special. Use `-entropy` to change the threshold in bits per byte (default 3.3). A higher threshold adds fewer entries. Set the option to `0` to turn the check off.

The command shows each added value in a masked form. Examine the list. A wrong entry causes the proxy to redact normal text. Remove a wrong entry with `hygienics secret remove`.

### Key files

At start, the proxy reads the private keys in `~/.ssh` and these credential files:

`~/.aws/credentials`, `~/.netrc`, `~/.git-credentials`, `~/.config/git/credentials`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gh/hosts.yml`, `~/.fly/config.yml`, `~/.config/gcloud/application_default_credentials.json`, `~/.terraform.d/credentials.tfrc.json`, `~/.cargo/credentials.toml`, `~/.vault-token`

The proxy adds each long value in these files to the secrets in memory. The proxy also redacts a long public value, for example a WireGuard public key. This is safe. The proxy does not write the keys to the secrets file. If a key goes into a request, the proxy redacts the key line by line.

### Pattern rules

Give a rule file in the [gitleaks format](https://github.com/gitleaks/gitleaks#configuration) with `-config`. Set `useDefault = true` to keep the default rules:

```toml
[extend]
useDefault = true

[[rules]]
id = "acme-token"
description = "ACME internal token"
regex = '''acme-[a-z0-9]{12}'''
```

## Deny file reads in Claude Code

The proxy is the last line of defense. Also stop Claude Code from reading the credential files. Add this to `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.netrc)", "Read(~/.git-credentials)",
      "Read(~/.npmrc)", "Read(~/.pypirc)", "Read(~/.docker/config.json)", "Read(~/.kube/**)",
      "Read(~/.config/gh/**)", "Read(~/.fly/**)", "Read(~/.config/gcloud/**)",
      "Read(~/.terraform.d/**)", "Read(~/.cargo/credentials.toml)", "Read(~/.vault-token)"
    ]
  }
}
```

The deny rule stops the Read tool. The proxy redacts the content when it arrives in another way, for example from a shell command.

## Run as a service

`make install` starts the proxy at login and restarts the proxy after a crash. On macOS the target writes a launchd agent. On Linux the target writes a systemd user unit. `make uninstall` removes the service.

## Logs

The proxy writes a log to `~/.config/hygienics/hygienics.log`. The log rotates. The log shows each request in which the proxy found a secret. The log shows the rule and a masked preview, never the secret.

```sh
hygienics logs             # print the full log
hygienics logs -n 50       # print the last 50 lines
```

Use `-log PATH` to change the file. Use `-log ""` to disable the file. Use `-log-lines N` to change the number of lines that the file keeps (default 10000).

## Options

| option       | default                          | description                                        |
| ------------ | -------------------------------- | -------------------------------------------------- |
| `-listen`    | `127.0.0.1:8787`                 | address to listen on                               |
| `-upstream`  | `https://api.anthropic.com`      | upstream API base URL                              |
| `-mode`      | `redact`                         | `redact` or `block`                                |
| `-config`    | embedded gitleaks rules          | gitleaks-format TOML rule file                     |
| `-secrets`   | `~/.config/hygienics/secrets`    | file with exact secret strings, one per line       |
| `-log`       | `~/.config/hygienics/hygienics.log` | log file, rotated; empty disables               |
| `-log-lines` | `10000`                          | maximum number of lines kept in the log file       |

Run `hygienics -h` to see the version and all commands.

## Shell completion

The `completion` command prints a completion script for bash and zsh.

For bash, add this line to `~/.bashrc`:

```sh
eval "$(hygienics completion)"
```

For zsh, add these lines to `~/.zshrc`:

```sh
autoload -U +X bashcompinit && bashcompinit
eval "$(hygienics completion)"
```

Then open a new shell. Push Tab to complete the commands and the options.

## Limits

- The proxy examines requests, not responses. Streamed responses pass through unchanged.
- The proxy sees only traffic that goes through `ANTHROPIC_BASE_URL`. The proxy does not cover other programs on the machine.
- A secret that a rule does not match, and that is not in the secrets file, goes through. Use `hygienics setup` and the secrets file to cover your own values.
- The placeholder replaces the secret in the text that the model sees. The model can not use the secret. This is the intent.
