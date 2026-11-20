# Settings

rerouted reads its settings from environment variables, and from a settings file named by `-env` (`.env` by default). A variable that's already set in the environment wins over the file. [`.env.example`](../.env.example) is a starting point with every setting.

rerouted checks its settings when it starts, and exits with a message naming the problem if one is wrong. To check a changed file before a reload or restart, run `rerouted config check`: it also flags likely typos in setting names.

## Reload settings without a restart

Send rerouted `SIGHUP` (with the packaged systemd unit, `sudo systemctl reload rerouted`; otherwise `kill -HUP PID`) to read the settings file and the environment again. A variable set in the environment still wins over the file. rerouted applies these settings at once:

- Registration: `REROUTED_REGISTRATION`, `REROUTED_REGISTRATION_CODE`, `REROUTED_REGISTRATION_PUBLIC`, and `REROUTED_PAUSE_MOVES`.
- Quotas: `REROUTED_MEDIA_QUOTA`, `REROUTED_BACKUP_QUOTA`, `REROUTED_COMMUNITY_FILE_DAYS`, `REROUTED_COMMUNITY_FILE_QUOTA`, and `REROUTED_COMMUNITY_HISTORY_QUOTA`.
- The call relay's credentials: `REROUTED_TURN_URLS` and `REROUTED_TURN_SECRET`.
- Community creation: `REROUTED_COMMUNITY_CODE` and `REROUTED_COMMUNITY_OPEN`.
- `REROUTED_TLS_ASK_ALLOW`, `REROUTED_LOG_LEVEL`, `REROUTED_UPDATE_CHECK`, and `REROUTED_RESTART_MAX_WAIT`.

Every other setting needs a restart. If one of them changed, rerouted logs a warning that names it, and keeps using its old value until the next restart. If the file has a mistake, rerouted logs the error and keeps all its current settings.

## Server

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_NAME` | None: required | This server's DNS name, such as `chat.example`. Never an IP address or a URL (SPEC §5.1). |
| `REROUTED_LISTEN` | `127.0.0.1:8080` | The address and port rerouted listens on, over plain HTTP. Put a reverse proxy in front for TLS. |
| `REROUTED_PUBLIC_URL` | `https://` + `REROUTED_NAME` | The origin clients and other servers reach the APIs at. It has to be `https://` outside dev mode. |
| `REROUTED_API_PATH` | `/.well-known/tieroute/v1/` | Where the wire version 1 APIs live under the public URL. The server document publishes them, so clients and other servers find them there (SPEC §8.1). |
| `REROUTED_API_PATH_V2` | `/.well-known/tieroute/v2/` | Where the wire version 2 APIs live, published beside version 1's. It has to differ from `REROUTED_API_PATH`. |
| `REROUTED_DATA_DIR` | `./data` | Where the database, files, and server key live. |
| `REROUTED_STORE` | `sqlite` | `sqlite` keeps everything in `REROUTED_DATA_DIR`. `temp` uses a throwaway database that's deleted on shutdown, for demos. |

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
| `REROUTED_TURN_URLS` | None, or the built-in relay's | The relay's `turn:` and `turns:` URLs, comma-separated (SPEC §15.1). Without them, `GET turn` answers `501`. With the built-in relay on and this unset, rerouted gives out `turn:NAME:PORT?transport=udp` and `turn:NAME:PORT?transport=tcp`, where `NAME` is `REROUTED_NAME` and `PORT` is the relay's port. |
| `REROUTED_TURN_SECRET` | None, or a generated one | The secret shared with the relay (coturn's `static-auth-secret`), at least 16 characters. Required with `REROUTED_TURN_URLS`. With the built-in relay on and this unset, rerouted makes a random secret and keeps it in `turn-secret` in `REROUTED_DATA_DIR`. |
| `REROUTED_TURN_LISTEN` | None: off | The address the built-in relay listens on, over UDP and TCP, such as `:3478`. Empty turns the built-in relay off. It doesn't do TLS, so it has no `turns:` URL. |
| `REROUTED_TURN_RELAY_PORTS` | `49160-49200` | The UDP ports the built-in relay sends and receives relayed media on, as `LOW-HIGH`. Each person in a relayed call uses about two. |
| `REROUTED_TURN_PUBLIC_IP` | The first of `REROUTED_VOICE_PUBLIC_IPS` | The public IP address clients reach the built-in relay's media at. Required with `REROUTED_TURN_LISTEN` unless `REROUTED_VOICE_PUBLIC_IPS` is set, or `REROUTED_TURN_LISTEN` names a public address. |

See [Run a call relay](run-a-call-relay.md).

## Push notifications

Notifications for the Reroute iPhone app, through Apple's push notification service (APNs). They're a rerouted feature, outside the Tieroute spec, and only a restart changes these settings.

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_APNS_KEY_FILE` | None: off | The path to the `.p8` APNs authentication key from the Apple developer account of the team that publishes the app. Empty turns push notifications off. It must be a PKCS #8 EC P-256 key that rerouted can read. |
| `REROUTED_APNS_KEY_ID` | None | The key's 10-character key ID. Required with `REROUTED_APNS_KEY_FILE`. |
| `REROUTED_APNS_TEAM_ID` | None | The team's 10-character team ID. Required with `REROUTED_APNS_KEY_FILE`. |
| `REROUTED_APNS_TOPIC` | `llc.rerouteholdings.reroute` | The app's bundle ID. Change it only for your own build of the app. |

See [Send push notifications to the Reroute iPhone app](push-notifications.md).

## Community servers

Beside its homeserver, rerouted can serve any number of server names as community servers (SPEC §16), each hosting one community. Each name answers as its own server, with its own server document listing the `community` role, its own composite server key (`community-key-NAME.json` in the data directory), and its own API base. A name equal to `REROUTED_NAME` is also the homeserver: one document lists both roles, with the homeserver's keys.

Point each name's DNS at the reverse proxy, and have the proxy pass the `Host` header on. rerouted tells the communities apart by that header, and approves certificates for them on demand.

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

## Outbound proxy

rerouted can send its outbound HTTP through a proxy. It reads the standard variables, not `REROUTED_` ones: federation with other servers, server and handle document fetches, push notifications to Apple, and the update check all honor them. A restart applies changes.

| Setting | Default | What it does |
|---|---|---|
| `HTTPS_PROXY` | None: direct | The proxy for `https://` requests, such as `http://proxy.example.com:3128` or `socks5://proxy.example.com:1080`. |
| `HTTP_PROXY` | None: direct | The proxy for plain `http://` requests, used only in development. |
| `NO_PROXY` | None | Hosts to reach directly, comma-separated, such as `example.org,.internal.example.com`. Requests to `localhost` and loopback addresses never use a proxy. |

The proxy only carries outbound requests. The call relay and community voice channels use UDP, and stay direct. `rerouted checkup` also connects directly, since it checks how other servers reach this one.

## Logging

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_LOG_LEVEL` | `info` | The least severe log messages to write: `debug`, `info`, `warn`, or `error`. |
| `REROUTED_LOG_FORMAT` | `text` | `text` writes `key=value` lines. `json` writes one JSON object per line, for log collectors. |

## Monitoring and upgrades

See [Monitor a homeserver](monitoring.md).

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_METRICS_LISTEN` | None: off | The address to serve metrics on, in the Prometheus text format, at `/metrics`, such as `127.0.0.1:9101`. Keep it on a private address. |
| `REROUTED_UPDATE_CHECK` | `off` | `on` checks once a day whether a newer rerouted has been released, and logs it if so. |
| `REROUTED_RESTART_MAX_WAIT` | `6h` | How long a restart asked for with `SIGUSR2` waits for voice calls to end before it restarts anyway, as a duration such as `90m` or `6h`. |

## Development

These let servers on one machine federate over plain HTTP. Never use them on a public server.

| Setting | Default | What it does |
|---|---|---|
| `REROUTED_DEV` | `off` | `on` allows `REROUTED_DEV_PEERS`, and a public URL that isn't `https://`. |
| `REROUTED_DEV_PEERS` | None | Servers to reach over plain HTTP, as `name=URL` pairs, comma-separated, such as `a.test=http://127.0.0.1:18091,b.test=http://127.0.0.1:18092`. |
