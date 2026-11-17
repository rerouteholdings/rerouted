# rerouted

rerouted is the reference homeserver for [Tieroute](https://rerouteholdings.llc/specs/tieroute), a federated, end-to-end encrypted (E2EE) chat protocol. This page says what rerouted implements, and where to start, whether you want to run it or work on it.

A *homeserver* holds its users' identities, and stores their messages until their devices fetch them. rerouted never needs to read a message: clients encrypt everything with Messaging Layer Security (MLS), and rerouted routes by the delivery envelope alone. It's written in Go, without cgo, and keeps its data in one SQLite database and a directory of files.

rerouted is alpha software, maintained by Reroute Holdings LLC. It runs the public alpha homeservers. It speaks Tieroute wire versions 1 and 2 side by side, each under its own API base. The current spec, version 2.0, defines wire version 2, with post-quantum signatures, a migration from wire version 1, and community servers. rerouted implements every version 2 endpoint in the spec's Appendix A, the migration from version 1, and community servers.

## Documentation

- [Run a homeserver](docs/run-a-homeserver.md): from a fresh Linux server to people signing up.
- [Run a call relay](docs/run-a-call-relay.md): relay your users' calls, so they don't show each other their IP addresses.
- [Administer a homeserver](docs/administer-a-homeserver.md): back up, control registration, and handle reports.
- [Settings](docs/settings.md): every setting, its default, and what it does.
- [Public firehose](docs/public-firehose.md): an optional public feed of delivery metadata, for development servers.
- [How rerouted stores moves and recovery wraps](docs/moves-and-recovery-wraps.md): how the multi-record changes stay consistent.

The protocol itself is documented in the [Tieroute specification](https://rerouteholdings.llc/specs/tieroute), the [client API reference](https://rerouteholdings.llc/specs/client), and the [server-to-server API reference](https://rerouteholdings.llc/specs/s2s).

## What it implements

rerouted implements every wire version 1 and version 2 endpoint in the spec's Appendix A, for clients and for other servers. Comments in the code cite the spec section each rule comes from, such as `SPEC §11.6`. Section numbers are those of the current spec.

| Area | Spec | What rerouted does |
|---|---|---|
| Encoding | §4 | I-JSON (the Internet JSON profile) with duplicate-name, UTF-8, and integer checks; strict base64url; and the JSON Canonicalization Scheme (JCS) for everything signed or hashed |
| Discovery | §5, §8.1 | The server document and handle documents. Reserved handles can't be registered. Handle changes: a new name under the handle domain has to be free, and a name an identity stops using, by a rename or a move away, is held for it for 30 days, then freed unless the operator keeps it (`keep-handle`). |
| Identities | §6 | Identity chains and the fork rule, vouching, tombstones, recovery with the recovery key, alerts on device changes, and moves between homeservers |
| Devices | §7 | Two-way device approval with link proofs, including approval codes a new device scans (listed with `GET link/proofs`), wrapped account keys, versioned account data, and backups |
| Contacts | §9 | Registration and contact requests by invite code; accept, decline, cancel, remove, block, and unblock; and the rate limits |
| Delivery | §10 | Send, inbox, acknowledge, and a WebSocket stream. Deliveries to other servers wait in a durable outbox, and are retried with backoff for up to 72 hours. |
| Groups | §11 | The hub, which orders a group's changes, with epoch keys and signed receipts; commits through a remote hub; missed commits; and hub handoff |
| Presence and profiles | §13 | Presence for mutual contacts only, and signed profiles with checked profile pictures |
| Files | §14 | Uploads up to 64 MiB under a quota for each identity, fetched through the recipient's own homeserver and deleted after 30 days |
| Calls | §15.1 | Time-limited credentials for a TURN (Traversal Using Relays around NAT) relay |
| Reports | §17 | Reports kept for the operator, and optionally forwarded to the reported identity's homeserver |
| Community servers | §16 | Every endpoint in the community server API, for any number of server names, each hosting one community: the community chain checked as the server must check it, the hub for the members group and restricted channels' groups with code joins' external commits, channel sequence numbers, history segments, read positions, files, reports, and voice channels through an SFU (selective forwarding unit) on Pion WebRTC |

What isn't built yet:

- Migrating to a version 2 identity on another server. It starts on the version 1 identity's homeserver, and moves afterwards.
- The public firehose shows wire version 1's deliveries only.
- Batching several deliveries into one server-to-server `deliver` call. Each call carries one, which the spec allows.
- Registration codes with use counts or expiry dates. There's one code, `REROUTED_REGISTRATION_CODE`.
- Combining presence updates for each destination server. A small server may send each one right away (SPEC §13.2).
- A rate limit on `recover` for each identity and address.


## Try it locally

You need Go, at the version in [`go.mod`](go.mod).

1. Build rerouted:

   ```sh
   go build -o rerouted ./cmd/rerouted
   ```

2. Start it with a throwaway database:

   ```sh
   REROUTED_NAME=chat.example REROUTED_STORE=temp ./rerouted -env /dev/null
   ```

3. In another terminal, fetch its server document:

   ```sh
   curl -s http://127.0.0.1:8080/.well-known/tieroute/server
   ```

   It prints a JSON object that starts with `{"apis":`.

To run it for real, follow [Run a homeserver](docs/run-a-homeserver.md).

## Develop

Check and test your changes:

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

Tests run against real SQLite databases in temporary directories, and the federation tests start two homeservers in one process. The files in `testdata/vectors/` are copies of the spec's test vectors for wire version 1, and those in `testdata/vectors/v2/` are for wire version 2.

| Path | What's there |
|---|---|
| `cmd/rerouted/` | The server and its admin commands |
| `cmd/linetest/` | A scripted client that drives two homeservers over HTTP, for end-to-end tests |
| `internal/api/` | HTTP routes and handlers, one file for each area of the API |
| `internal/chain/` | Identity chains: validation, the fork rule, alerts, and clock checks |
| `internal/fed/` | Federation: server documents, signed server-to-server calls, and handle resolution |
| `internal/store/` | The storage interface, and its SQLite implementation in `sqlite/` |
| `internal/wire/` | JSON encoding, signed envelopes, identifiers, chain entries, and error codes |
| `internal/ws/` | The server side of the WebSocket protocol (RFC 6455), on the standard library |
| `internal/config/`, `internal/serverkey/` | Settings, and the server's signing key |
| `deploy/` | Example systemd, Caddy, and coturn configurations |
| `docs/` | Guides and reference for operators |

Before you send a change, read [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, follow [SECURITY.md](SECURITY.md), and don't open a public issue.

## License

You can use rerouted under the MIT license. See [LICENSE](LICENSE). Reroute Holdings LLC also pledges never to assert its patents against Tieroute implementations: see [PATENTS.md](PATENTS.md).
