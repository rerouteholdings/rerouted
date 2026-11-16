# rerouted

rerouted is the reference homeserver for [Tieroute](https://rerouteholdings.llc/specs/tieroute), a federated, end-to-end encrypted (E2EE) chat protocol. This page says what rerouted implements, and where to start, whether you want to run it or work on it.

A *homeserver* holds its users' identities, and stores their messages until their devices fetch them. rerouted never needs to read a message: clients encrypt everything with Messaging Layer Security (MLS), and rerouted routes by the delivery envelope alone. It's written in Go, without cgo, and keeps its data in one SQLite database and a directory of files.

rerouted is alpha software, maintained by Reroute Holdings LLC. It runs the public alpha homeservers. It speaks Tieroute wire versions 1 and 2 side by side, each under its own API base. The current spec, version 2.0, defines wire version 2, with post-quantum signatures, a migration from wire version 1, and community servers. rerouted implements every version 2 endpoint in the spec's Appendix A, the migration from version 1, and community servers.

## Documentation

- [Run a homeserver](docs/run-a-homeserver.md): from a fresh Linux server to people signing up.
- [Run a call relay](docs/run-a-call-relay.md): relay your users' calls, so they don't show each other their IP addresses.
- [Administer a homeserver](docs/administer-a-homeserver.md): back up, control registration, and handle reports.
- [Settings](docs/settings.md): every setting, its default, and what it does.
- [Security architecture](docs/security-architecture.md): the processes rerouted can be split into, what each can reach, and what a takeover of each gets.
- [Public firehose](docs/public-firehose.md): an optional public feed of delivery metadata, for development servers.
- [How rerouted stores moves and recovery wraps](docs/moves-and-recovery-wraps.md): how the multi-record changes stay consistent.

The protocol itself is documented in the [Tieroute specification](https://rerouteholdings.llc/specs/tieroute), the [client API reference](https://rerouteholdings.llc/specs/client), and the [server-to-server API reference](https://rerouteholdings.llc/specs/s2s).

## What it implements

rerouted implements every wire version 1 endpoint in the spec's Appendix A, for clients and for other servers. Comments in the code cite the spec section each rule comes from, such as `SPEC §11.6`. Section numbers are those of the current spec; where version 2.0 changed a rule, the version 1 API follows wire version 1.

The wire version 2 API serves the same endpoints for version 2 identities: composite ML-DSA-65 + Ed25519 signatures (§3.2), chains with composite device keys, the 10-device ceiling, and recovery forks of any age (§6.4), key packages with their `kp-binding` (§3.2.2), S2S calls signed with a composite server key (§8.3), and the hub (§11.6) with composite epoch keys: `epoch-key`, `next`, and `reg` are composite public keys, a `commit-request` or `epoch-key` carries its whole composite key in `k`, and commit receipts are signed with the composite server key. Profiles, moves, and link proofs are signed with composite device keys, a recovery wrap's `commit` is the hash of the code's composite recovery key 1, and a report's evidence is the app-message, signed by a message key, with its `msg-key` (§17.3). Account data, backups, files, presence, and call relay credentials are as in version 1. A hub keeps each version's groups apart, but a group ID registered in either is taken in both. On the version 2 API, `POST send` refuses an MLS PublicMessage with `bad-request` (§10.1), since only a community code join sends one. The two versions keep their identities apart, and neither accepts the other's signatures (§5.1). Handles are one namespace across both.

A version 1 identity migrates to version 2 (§6.8) in one request: the version 1 `POST chain/append` that carries `migrate` also carries the version 2 genesis it names, in `genesis`. One transaction appends the entry, registers the version 2 identity on the same server, hands it the handle, and copies the contact and group allowlists, so neither half can be left without the other. The version 2 `POST register` with that genesis only confirms a migration that happened (`200`), and before it answers `403 not-allowed`. After it:

- The version 1 chain is closed: any later entry is `400 invalid-chain`, and no recovery fork can override the `migrate`. The entry that carries `migrate` carries no other op, except a recovery-signed entry's `set-recovery`.
- Deliveries, key-package claims, and contact requests for the version 1 identity are refused with `410 migrated` (SPEC §6.8, and the error registry in the API conventions). A delivery refused by another server reaches the sender's devices as a `delivery-failed` event with reason `migrated`. The version 1 identity can't send, but its devices can still read its version 1 inbox.
- On the version 1 API its handle doesn't resolve (`404`). On the version 2 API it resolves to the version 2 identity, as does a handle record that still names the version 1 identity.
- A contact that has migrated too is listed under its version 2 identifier, on both servers: at the migration, when another server pushes a closed version 1 chain, and when a version 2 client lists its contacts. Contacts that haven't migrated stay listed under their version 1 identifiers until they do, and changes to the version 2 identity's chain are pushed to their servers meanwhile.
- A version 2 client can fetch a closed version 1 chain with `GET chain/{id}`, to check the link.

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

## Community servers

Set `REROUTED_COMMUNITIES` to the names to serve (see [Settings](docs/settings.md#community-servers)). The API is in the [community server API reference](https://rerouteholdings.llc/specs/community). Where the spec and that reference leave a choice open, rerouted does this:

- Requests reach a community by their `Host` header. A name that's only a community server answers `501` on its S2S base, and fetches identity chains from their homeservers with S2S `identity/fetch`, signed with its own key: at every sign-in, and at least once a day for each identity with a session. Members read its copy of each other's chains with `GET members/{id}/chain`, former members' included: those who left, were kicked, or were banned here, and the community chain's signers. A device removed from its chain loses its sessions, stream, and voice at once.
- The chain (`internal/cchain`) follows §16.2.2's checks and error table. The §16.1 limits all answer `403 not-allowed`; an edit with nothing to change, `400 bad-request`; other rule breaks, `400 invalid-chain`. A domain ban that's already there is `invalid-chain`, like a member's. Names and descriptions count Unicode code points.
- A ban removes the banned identity, and every member a domain ban covers except the owner, in the append's own transaction.
- Code access needs a session, and a code whose creator is still a member here. Joins count each code's uses and the 1,000-member cap in the same transaction as the hub step.
- A timed-out member can't send to channels, upload, send a voice key, or cast, but can still send protocol traffic without a channel, and join a voice channel to listen.
- A device gets a group's traffic only from its registration on. A Welcome registers its devices; the device that creates a group is registered for it.
- Moving in takes `homes`, the homeservers of the chain's signers it may not know, and accepts any device a signer's chain added, as a client does. Only the identities on the owner's signed member list become members by registering for the members group. The old server answers the `set-home` with each text channel's last sequence number (`seqs`), and the new one takes them with the move-in and numbers on from there.
- A move reservation (`POST create` with `check`) holds the name for its community for 30 days after it expires, in the database; the community's move-in ends the hold. Releasing one by hand means deleting its row from `cm_holds`. The old server checks the reservation, fetching the new server's document, while it holds its append lock.
- A community that moved away answers `410 expired` to everything but `GET chain`, sessions, and what its hub handoff needs. Messages and appends get `409 wrong-home`; a `set-home`'s append waits for sends already under way, so none is numbered past its `seqs`.
- History over the quota is refused, not trimmed. `replace` works only for a segment with the same start and end, after a delete recorded inside it.
- An approval's claimed key packages are kept in memory for its 10 minutes, so a retry after a restart claims new ones.
- Voice: a device is in one voice channel at a time. The cast limit counts devices, and losing the right to speak ends a cast. The server keeps its own offer when offers cross. Who may speak is checked again every 5 seconds, so a timeout's end takes effect.
- Rate limits: 120 appends an hour per identity, 30 sign-in challenges an hour, 10 failed joins an hour per identity and 100 per origin domain, 5 tree uploads an hour for non-members, 50 key package claims a day per claimant and target, 50 reports a day, 1,200 read positions sent and 600 fetches an hour per identity, and 1,000 pending join requests.

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
| `cmd/rerouted-keyd/` | An optional process that holds the server keys and signs for rerouted |
| `cmd/rerouted-sfu/` | An optional process that runs voice channels' SFU for rerouted |
| `cmd/rerouted-egress/` | An optional process that makes rerouted's connections out, so rerouted can run without a network |
| `cmd/linetest/` | A scripted client that drives two homeservers over HTTP, for end-to-end tests |
| `internal/api/` | HTTP routes and handlers, one file for each area of the API |
| `internal/chain/` | Identity chains: validation, the fork rule, alerts, and clock checks |
| `internal/fed/` | Federation: server documents, signed server-to-server calls, and handle resolution |
| `internal/store/` | The storage interface, and its SQLite implementation in `sqlite/` |
| `internal/wire/` | JSON encoding, signed envelopes, identifiers, chain entries, and error codes |
| `internal/ws/` | The server side of the WebSocket protocol (RFC 6455), on the standard library |
| `internal/config/`, `internal/serverkey/` | Settings, and the server's signing key |
| `internal/keyd/` | rerouted-keyd: what it signs, its socket protocol, and its encrypted key bundle |
| `internal/sfu/`, `internal/sfuipc/` | Voice channels' SFU, on Pion WebRTC, and running it in rerouted-sfu |
| `internal/egress/` | rerouted-egress: its policy, and the dialer and TXT lookup rerouted uses through it |
| `internal/ipc/` | Messages, peer checks, and socket activation for rerouted's processes |
| `deploy/` | Example systemd, Caddy, and coturn configurations, and AppArmor and SELinux policies |
| `docs/` | Guides and reference for operators |

Before you send a change, read [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, follow [SECURITY.md](SECURITY.md), and don't open a public issue.

## License

You can use rerouted under the MIT license. See [LICENSE](LICENSE). Reroute Holdings LLC also pledges never to assert its patents against Tieroute implementations: see [PATENTS.md](PATENTS.md).
