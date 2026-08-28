# hygienics

Work in progress, subject to change.

hygienics is a local proxy for Claude Code. The proxy examines each request before the request goes to Anthropic. If the proxy finds a secret, the proxy removes the secret or stops the request.

## Operation

1. Build the program:
   ```sh
   go build -o hygienics .
   ```
2. Start the proxy:
   ```sh
   ./hygienics                # listen on 127.0.0.1:8787, remove secrets
   ./hygienics -mode block    # stop each request that contains a secret
   ```
3. Set the environment variable and start Claude Code:
   ```sh
   export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
   claude
   ```

## Custom secrets

### Exact strings

Write each secret on one line in the file `~/.config/hygienics/secrets`. Or give a different file with the `-secrets` option. The proxy ignores blank lines and lines that start with `#`:

```
# do not send these
abc123
my-internal-db-password
```

The proxy removes or stops each request that contains one of these strings. A pattern is not necessary.

Use the `secret` command to change the file:

```sh
./hygienics secret add       # add a secret
./hygienics secret remove    # remove a secret
./hygienics secret list      # show each secret in a masked form
./hygienics secret path     # show the path of the secrets file
```

The `add` and `remove` commands show the prompt `enter secret`. Type the secret, then push Enter. The command does not accept the secret as an argument. Thus the secret does not go into the shell history.

## Review the log

The proxy writes a rolling log to `~/.config/hygienics/hygienics.log`. The log shows each request in which the proxy found a secret. Use the `logs` command to read it:

```sh
./hygienics logs             # print the full log
./hygienics logs -n 50       # print the last 50 lines
```

Use `-log <path>` when you start the proxy to change the file. Use `-log ""` to disable the file. Use `-log-lines` to change the number of lines that the file keeps (default 10000).

Use the `-secrets` option to select a different file: `./hygienics secret -secrets FILE add`.

### Automatic setup

The `setup` command examines the environment variables:

```sh
./hygienics setup
```

The command applies the gitleaks rules to each `NAME=value` pair. The variable name gives context that a request body does not have. For example, the name `DB_PASSWORD` marks the value as a secret. The command adds each found value to the secrets file. The command ignores short values, paths, and common shell variables.

The command also makes an entropy check. A value with high entropy counts as a secret, also when no rule matches and the variable name is not special. Use the `-entropy` option to change the threshold in bits per byte (default 3.3). A higher threshold adds fewer entries. Set the option to `0` to turn the check off.

The command shows each added value in a masked form. Examine the list. A wrong entry causes the proxy to redact normal text. Remove a wrong entry with `./hygienics secret remove`.

### Pattern rules

Give a rule file in the gitleaks format with the `-config` option. Set `useDefault = true` to keep the default rules:

```toml
[extend]
useDefault = true

[[rules]]
id = "acme-token"
description = "ACME internal token"
regex = '''acme-[a-z0-9]{12}'''
```

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

## Detection

The default rules come from [gitleaks](https://github.com/gitleaks/gitleaks). The set has approximately 220 rules and includes entropy checks. The proxy replaces each secret with `[REDACTED:<rule>:<hash>]`. The replacement is always the same for the same secret. Thus the prompt cache of Anthropic continues to operate.

Refer to `RESEARCH.md` for the design decisions.
