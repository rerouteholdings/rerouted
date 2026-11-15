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

Code that reads what arrives from the network has fuzz targets: JSON and signed envelopes (`internal/wire`), WebSocket frames (`internal/ws`), identity and community chain entries (`internal/chain`, `internal/cchain`), and rerouted-keyd's requests (`internal/keyd`). `go test` runs their seeds, and CI fuzzes each for a minute. To fuzz one longer:

```sh
go test -run '^$' -fuzz '^FuzzRead$' -fuzztime 10m ./internal/ws
```

A failing input is saved under the package's `testdata/fuzz/`. Commit it with the fix: `go test` then runs it every time.

## Code

- Run `gofmt`. CI checks it, along with `go vet`, `staticcheck`, and `govulncheck`.
- Cite the spec where behavior comes from it, by section: `// SPEC §11.6`.
- Comments say why, not what. Keep them to what a reader needs to change the code safely.
- Every behavior change comes with a test. A protocol rule gets a test that breaks it and checks the server refuses.
- Keep dependencies few. Anything new needs a reason.

## CI and releases

- Actions in `.github/workflows/` are pinned to commits, with the release in a comment. Dependabot proposes updates, for actions and Go modules, once a week. Pin any new action the same way.
- Pushing a tag such as `v0.2.0` runs `release.yml`. It builds `rerouted`, `rerouted-keyd`, and `rerouted-sfu` for Linux on amd64 and arm64 with `.github/build-release.sh`. It builds them again on another runner and fails unless every byte matches, and attests their provenance. Anyone can check a binary with `gh attestation verify FILE --repo rerouteholdings/rerouted`, or rebuild it with the same Go version and that script.

## Pull requests

Keep each one to one change, with a description of what it does and why. By contributing, you agree that your work is licensed under MIT.
