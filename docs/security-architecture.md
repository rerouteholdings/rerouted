# Security architecture

This page describes how rerouted is split into processes, what each one can reach, and what someone who takes one over gets. It's for operators deciding how to deploy it, and for anyone reviewing it. To report a problem, see [SECURITY.md](../SECURITY.md).

rerouted never sees message content: chats, files, and backups are end-to-end encrypted. What a homeserver holds is metadata (who talks to whom, contacts, groups, presence), its users' sessions, and its own signing keys. The design below is about those.

## The processes

`rerouted` alone is a complete homeserver. Each of the other three is optional, and takes one thing away from it. [Run a homeserver](run-a-homeserver.md) has the steps.

| Process | Runs as | Holds | Network | Can write |
|---|---|---|---|---|
| `rerouted` | `rerouted` | The database and files. Parses every request. | With all three others: none. Its listening socket comes from systemd, and it has unix sockets only. | Its data directory |
| `rerouted-keyd` | `rerouted-keyd` | The server keys, decrypted by systemd from a file only this machine can read | None | Nothing |
| `rerouted-sfu` | `rerouted-sfu` | Nothing. Forwards voice channels' media, which is encrypted end to end. | UDP. Nothing to this host or to link-local addresses. | Nothing |
| `rerouted-egress` | `rerouted-egress` | Nothing. Copies bytes of connections that are TLS between rerouted and the other server. | TCP out and DNS. Never link-local addresses. | Nothing |

Each has its own user, its own systemd sandbox, and its own AppArmor profile or SELinux domain. They talk over unix sockets that systemd creates. A socket lets in rerouted's group, and the process behind it then checks that the caller is rerouted's user. None of the three is in that group, so none can open another's socket.

## What a takeover gets

| If someone takes over | They get | They don't get |
|---|---|---|
| `rerouted` | The database: metadata, sessions, and everything stored. Signatures from rerouted-keyd while they're in, of the four kinds a server makes, for this server's name, valid for minutes. Connections out to public addresses. | The server keys, so nothing they sign outlives them. Other machines on your network, or cloud metadata. Message content. |
| `rerouted-sfu` | Voice channels' traffic patterns, and their SFrame ciphertext. The ability to drop or misroute media. | Keys, the database, settings, or a way to reach this host's services. What's said in a channel. |
| `rerouted-egress` | The ability to see where rerouted connects, and to drop connections. The settings file's contents, which it read at start. | The content of connections: TLS ends in rerouted. Keys or the database. |
| `rerouted-keyd` | The server keys. | The database. It has no network, so the keys leave only through rerouted. |

Without the optional processes, a takeover of `rerouted` gets all of it: that's the case the split is for.

## What rerouted checks itself

- **Other servers' names** are DNS names and nothing else, wherever they come from. A name goes into a URL, so one with a port or a path would choose where a request goes.
- **Connections out** go to public addresses only, checked on the address actually dialed, so DNS can't answer differently between the check and the connection. `REROUTED_FED_ALLOW` lists exceptions. Redirects stay on HTTPS.
- **What a name can cost** is bounded before anything is authenticated: a server's document is fetched once at a time, a failed fetch is remembered for 10 seconds, 64 are fetched at once, the cache holds 16 MiB, and responses over 1 MiB are read 6 at a time.
- **JSON** is I-JSON, with names matched exactly, no lone surrogates, and at most 128 levels of nesting. Whatever rerouted accepts, a stricter reader accepts too, and reads the same way.
- **Request bodies** have size limits and deadlines. Responses tell browsers to run and load nothing.
- **Guesses** at a registration code, a community's creation code, an invite, or a sign-in code are counted and cut off: per address (IPv6 by /64), identity, or home server.
- **Sessions** are random tokens stored as hashes. Secrets are compared in constant time.

The parsers that read what arrives from the network have fuzz targets, which CI runs on every change ([CONTRIBUTING.md](../CONTRIBUTING.md)).

## Behind a reverse proxy

Per-address limits count the address your proxy saw connect: the last entry of `X-Forwarded-For`, and only when the request comes from this machine. Caddy sets the header to exactly that. If another proxy or a CDN sits in front of it, everyone behind that hop shares its address, and its limits: have the proxy nearest rerouted pass the real one.

## Not done yet

These would each make a takeover less useful, or less likely. None is in rerouted today.

- **Server key rotation.** A key that's been exposed can't be replaced without losing invite codes, and there's no way to publish a new key ahead of time. This is the largest gap: rerouted-keyd lowers the odds of exposure, and rotation is what limits the damage.
- **The database in its own process.** rerouted parses every request and also holds every row. A storage process that enforced who may read what would mean a parser bug exposes one session's data, not all of it.
- **A separate socket for the proxy's own calls.** `/v0/tls-ask` is on the public listener, and the reverse proxy is trusted to block it.
- **An audit log.** Refusals are logged where they happen (rerouted-keyd, rerouted-egress), but there's no single record of sign-ins, device changes, and operator commands.
- **Self-sandboxing.** The limits come from systemd and the MAC policies. Run by hand, or in a container without them, rerouted has none: Landlock and seccomp from inside would cover that.
- **Encrypted DNS and DNSSEC** for handle lookups, which plain DNS can forge.
- **Encryption of the database at rest**, beyond what the disk provides.
