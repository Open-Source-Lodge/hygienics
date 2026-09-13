# Development

## Build and test

```sh
make build
make test
make lint
```

## Layout

- `cmd/hygienics/` is the command: flags, subcommands, `main()`. Use `go build ./cmd/hygienics` to build without make.
- `internal/scan/` detects secrets in bytes, credential files and the environment.
- `internal/proxy/` is the HTTP handler that redacts or blocks a request.
- `internal/logfile/` is the size-bounded log file.

## Commit messages

Write the commit messages in the Conventional Commits format. The release
tool reads the commit types to select the version number.

## Release

The `release` workflow runs [release-please](https://github.com/googleapis/release-please)
each time a pull request merges to `main`. Release-please reads the commit
messages since the last release. Release-please selects the version number
with these rules:

| commit message                                | version change |
| --------------------------------------------- | -------------- |
| `feat!:` or a `BREAKING CHANGE:` footer       | major          |
| `feat:`                                       | minor          |
| `fix:` or `perf:`                             | patch          |
| other types, such as `docs:` or `ci:`         | no release     |

Release-please opens a release pull request. The pull request updates
`CHANGELOG.md` with the new version. Merge the release pull request to make
the tag, such as `v1.2.3`, and the GitHub release.

When you merge the release pull request, the `binaries` job builds `hygienics`
for macOS, Linux and Windows, on the amd64 and arm64 architectures. The job
attaches the binaries and `checksums.txt` to the GitHub release. The job also
sets the version in the binaries, so that `hygienics -h` shows the tag.

## Dependabot

Dependabot opens one pull request each week for the Go modules and one for the
actions. The commits use the `chore:` type. A `chore:` commit makes no release.

Refer to [RESEARCH.md](RESEARCH.md) for the design decisions and sources.
