# Secret sources are opt-in

## Why

The proxy runs on the machine of the user and can read private keys, credential files and environment variables. A user must know each place the proxy reads and must agree to it. A source that is on by default reads secrets that the user did not expect, and the user cannot see this from the outside.

## What the rule covers

- The secrets file (`-secrets`) is the only source that the proxy reads without a flag.
- The proxy reads the key files in the home directory only with `-discover` or `discover = true` in the `-config` file.
- Only the `hygienics setup` command reads the environment.
- `loadSecrets` in `cmd/hygienics/main.go` is the single place that loads secrets for the proxy. `TestLoadSecretsOptIn` in `cmd/hygienics/main_test.go` guards it. A change that adds a source also changes the test and the `README.md`.

## What the rule does not cover

- The gitleaks rule set and the `-config` rule file. These hold patterns, not secrets.
- Reads that do not look for secrets, for example the log file and the `HOME` variable.
