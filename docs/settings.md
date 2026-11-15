# Settings

rerouted reads its settings from environment variables, and from a settings file named by `-env` (`.env` by default). A variable that's already set in the environment wins over the file. [`.env.example`](../.env.example) is a starting point with every setting.

rerouted checks its settings when it starts, and exits with a message naming the problem if one is wrong.

## Server

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_NAME` | None: required | This server's DNS name, such as `chat.example`. Never an IP address or a URL (SPEC §5.1). |
| `REROUTED_LISTEN` | `127.0.0.1:8080` | The address and port rerouted listens on, over plain HTTP. Put a reverse proxy in front for TLS. |
| `REROUTED_PUBLIC_URL` | `https://` + `REROUTED_NAME` | The origin clients and other servers reach the APIs at. It MUST be `https://` outside dev mode. |
| `REROUTED_API_PATH` | `/.well-known/tieroute/v1/` | Where the wire version 1 APIs live under the public URL. The server document publishes them, so clients and other servers find them there (SPEC §8.1). |
| `REROUTED_API_PATH_V2` | `/.well-known/tieroute/v2/` | Where the wire version 2 APIs live, published beside version 1's. It has to differ from `REROUTED_API_PATH`. |
| `REROUTED_DATA_DIR` | `./data` | Where the database, files, and server key live. |
| `REROUTED_STORE` | `sqlite` | `sqlite` keeps everything in `REROUTED_DATA_DIR`. `temp` uses a throwaway database that's deleted on shutdown, for demos. |
| `REROUTED_FED_ALLOW` | None | Networks other servers may be reached at although they aren't on the public internet, as addresses or CIDR prefixes, comma-separated, such as `10.20.0.0/16`. Outside dev mode, rerouted refuses to connect to loopback, link-local, private, and other non-global addresses otherwise, so nobody can point a server name or a redirect at this host's or its network's internal services. A proxy set with `HTTPS_PROXY` needs its address listed here if it's on such a network. |

## Identities and registration

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_HANDLES` | None | The domain to give out handles under, such as `chat.example` for `@kat.chat.example`. It needs wildcard DNS and TLS for its subdomains. |
| `REROUTED_REGISTRATION` | `closed` | `invite`: people sign up with the registration code. `closed`: nobody can sign up (SPEC §8.2). |
| `REROUTED_REGISTRATION_CODE` | None | The registration code, at least 10 characters. Required when registration is `invite`. |
| `REROUTED_REGISTRATION_PUBLIC` | `off` | `on` publishes the code in the server document, so anyone can sign up. |
| `REROUTED_PAUSE_MOVES` | `off` | `on` refuses device-signed moves to and from this server (SPEC §6.6). Recovery-signed entries still go through. |

## Storage quotas

Sizes are a number of bytes, or a number with a `K`, `M`, or `G` suffix for KiB, MiB, or GiB.

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_MEDIA_QUOTA` | `1G` | Bytes of files each identity may store (SPEC §14). |
| `REROUTED_BACKUP_QUOTA` | `1G` | Bytes of backups each identity may store (SPEC §7.5). |

## Call relay

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_TURN_URLS` | None | The relay's `turn:` and `turns:` URLs, comma-separated (SPEC §15.1). Without them, `GET turn` answers `501`. |
| `REROUTED_TURN_SECRET` | None | The secret shared with the relay (coturn's `static-auth-secret`), at least 16 characters. Required with `REROUTED_TURN_URLS`. |

See [Run a call relay](run-a-call-relay.md).

## Community servers

rerouted can serve any number of server names as community servers (SPEC §16), each hosting one community, beside its homeserver. Each name answers as its own server: its own server document, listing the `community` role, its own composite server key (`community-key-NAME.json` in the data directory), and its own API base. A name equal to `REROUTED_NAME` is also the homeserver, with both roles in one document and the homeserver's keys. Point each name's DNS at the reverse proxy, which passes the `Host` header on: rerouted tells the communities apart by it, and says yes to certificates for them on demand.

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_COMMUNITIES` | None | The community server names, comma-separated. Each is `name`, or `name=URL` to be reached at an origin other than `https://name`. In dev mode, a URL with a host and port of its own gets a listener of its own. |
| `REROUTED_COMMUNITY_CODE` | None | The creation code `POST create` needs, at least 10 characters. Give it to whoever will own each community. |
| `REROUTED_COMMUNITY_OPEN` | `off` | `on` lets anyone who signs in create the community on a name that hasn't one yet. Required with `REROUTED_COMMUNITIES` if there's no creation code. |
| `REROUTED_COMMUNITY_FILE_DAYS` | `30` | How many days files in channels are kept. `0` keeps them until their message is deleted. |
| `REROUTED_COMMUNITY_FILE_QUOTA` | `10G` | Bytes of files each community may store. Uploads past it get `413 over-quota`. |
| `REROUTED_COMMUNITY_HISTORY_QUOTA` | `10G` | Bytes of history segments each community may store. Uploads past it get `413 over-quota`; stored segments are kept. |
| `REROUTED_VOICE_UDP_PORT` | `0` | One UDP port that carries every voice connection, to open in a firewall. `0` uses a random port for each connection. |
| `REROUTED_VOICE_PUBLIC_IPS` | None | The public addresses to advertise for voice behind 1:1 NAT, comma-separated. |

## Certificates on demand

A reverse proxy that gets certificates on demand, such as Caddy, can ask rerouted at `GET /v0/tls-ask?domain=NAME` whether to issue one. rerouted says yes for its own name, for handles registered on it, and for the names below.

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_TLS_ASK_ALLOW` | None | Other hostnames under the handle domain that may get certificates, such as a website at `www.chat.example`. Comma-separated. |
| `REROUTED_TLS_ASK_ALSO` | None | The base URLs of other rerouted instances on the same host to ask too, such as `http://127.0.0.1:8081`, when the proxy can only ask one. Comma-separated. |

## Public firehose

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_PUBLIC_FIREHOSE` | `off` | `on` serves a public feed of the metadata of every delivery stored here. See [Public firehose](public-firehose.md) before turning it on. |

## Development

These let servers on one machine federate over plain HTTP. Never use them on a public server.

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_DEV` | `off` | `on` allows `REROUTED_DEV_PEERS`, and a public URL that isn't `https://`. |
| `REROUTED_DEV_PEERS` | None | Servers to reach over plain HTTP, as `name=URL` pairs, comma-separated, such as `a.test=http://127.0.0.1:18091,b.test=http://127.0.0.1:18092`. |
