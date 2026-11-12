# Contributing

This page explains how to build and test rerouted, and how to send us a change.

rerouted is the reference homeserver for Tieroute, so its job is to follow the spec exactly. A change to the protocol goes to the spec first, and rerouted follows.

## Before you start

- For anything larger than a small fix, open an issue first, so we can agree on the approach before you write it.
- Security problems go through a private report, never an issue (see [SECURITY.md](SECURITY.md)).

## Build and test

You need Go (the version in `go.mod`). No cgo: SQLite is the pure-Go `modernc.org/sqlite`.

```sh
go build ./cmd/rerouted
go vet ./...
go test -race ./...
```

Tests run against real SQLite databases in temporary directories, and federation tests start two servers in-process.

## Code

- Run `gofmt`. CI checks it, along with `go vet`, staticcheck, and govulncheck.
- Cite the spec where behaviour comes from it, by section: `// SPEC §11.6`.
- Comments say why, not what. Keep them to what a reader needs to change the code safely.
- Every behaviour change comes with a test. A protocol rule gets a test that breaks it and checks the server refuses.
- Keep dependencies few. Anything new needs a reason.

## Pull requests

Keep each one to one change, with a description of what it does and why. By contributing, you agree that your work is licensed under MIT.
