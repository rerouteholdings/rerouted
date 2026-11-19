# Monitor a homeserver

This page explains how to watch a running rerouted homeserver: its metrics, its status file, the optional update check, and how it restarts after an upgrade without cutting off voice calls.

## Metrics

rerouted can serve metrics in the Prometheus text format. They're off by default. To turn them on, set an address in the settings file and restart rerouted:

```sh
REROUTED_METRICS_LISTEN=127.0.0.1:9101
```

rerouted then serves `GET /metrics` on that address, on a listener of its own, apart from the APIs. The metrics have no authentication, so keep the address private: a loopback address, or one that only your monitoring network reaches. Point Prometheus, or any collector that reads the same format, at `http://127.0.0.1:9101/metrics`.

Every metric is an aggregate count. No metric or label names an identity, a handle, a device, a community, or another server.

| Metric | Type | What it counts |
|---|---|---|
| `rerouted_build_info` | gauge | Always `1`. Its `version` label is the running rerouted's version. |
| `rerouted_uptime_seconds` | gauge | Seconds since rerouted started. |
| `rerouted_identities` | gauge | Identities with a handle in use on this homeserver. |
| `rerouted_devices_signed_in` | gauge | Devices with a session that hasn't expired. |
| `rerouted_communities` | gauge | Communities on this server's community server names. |
| `rerouted_outbox_requests` | gauge | Server-to-server (S2S) requests waiting to be sent to other servers. |
| `rerouted_s2s_send_failures_total` | counter | S2S requests that failed or that the other server refused, since the start. Failed requests are retried for up to 72 hours. |
| `rerouted_streams` | gauge | Open `GET stream` connections (WebSockets), on both wire versions and every community. |
| `rerouted_voice_rooms` | gauge | Community voice channels with anyone in them. |
| `rerouted_voice_participants` | gauge | Devices in community voice channels. |
| `rerouted_http_responses_total` | counter | HTTP responses on the APIs, with a `class` label: `1xx`, `2xx`, `3xx`, `4xx`, or `5xx`. |
| `rerouted_database_bytes` | gauge | The database's size in bytes, without its write-ahead log. |
| `rerouted_turn_allocations` | gauge | Open allocations on the built-in call relay. Only there when the relay is on. |
| `rerouted_restart_pending` | gauge | `1` while a restart waits for voice calls to end. |
| `rerouted_update_available` | gauge | `1` once the update check has found a newer release. |

A rising `rerouted_outbox_requests` with a rising `rerouted_s2s_send_failures_total` usually means another server is down or can't be reached. The log names the server.

## Status file

While it runs, rerouted keeps a small JSON file at `status.json` in `REROUTED_DATA_DIR`. It writes the file when it starts, every 30 seconds, and whenever something in it changes, and it deletes the file when it shuts down cleanly. `rerouted status` reads it (add `--json` for scripts), along with counts from the database. The data directory is readable only by the `rerouted` user, so run it as that user or as root. For checks from the outside, such as DNS, certificates, and the call relay, run `rerouted checkup`. Local tools can read it too: rerouted replaces it in one step, so a reader never sees half a file.

For example:

```json
{"version":"0.2.0","pid":4812,"started":1795000000,"updated":1795000930,"name":"chat.example","listen":"127.0.0.1:8080","voice_rooms":1,"voice_participants":3,"outbox":0,"restart_pending":false,"update_available":"","metrics":"127.0.0.1:9101","turn":":3478"}
```

| Field | What it holds |
|---|---|
| `version` | The running rerouted's version. |
| `pid` | Its process ID. |
| `started`, `updated` | When it started, and when it last wrote the file, in Unix seconds. A file whose `updated` is more than about a minute old belongs to a server that stopped without cleaning up. |
| `name`, `listen` | `REROUTED_NAME` and `REROUTED_LISTEN`. |
| `voice_rooms`, `voice_participants` | Community voice channels with anyone in them, and the devices in them. |
| `outbox` | S2S requests waiting to be sent. |
| `restart_pending` | `true` while a restart waits for voice calls to end. |
| `update_available` | The newer version the update check found, or an empty string. |
| `metrics`, `turn` | The metrics address and the built-in call relay's address, or empty strings when they're off. |

## Update check

rerouted can check once a day whether a newer version has been released. The check is off by default. To turn it on, set this and reload or restart rerouted:

```sh
REROUTED_UPDATE_CHECK=on
```

A few minutes after it starts, and then once a day, rerouted fetches `https://rerouteholdings.llc/reroute/linux/rerouted/latest.json`. The request carries only a generic User-Agent with rerouted's version, such as `rerouted/0.2.0 (Tieroute homeserver; https://rerouteholdings.llc)`. It doesn't include the server's name or anything else about it, though the web server that answers sees the IP address the request comes from.

When a newer version is out, rerouted logs it once, at info level, with the version and a link to its release notes, and puts the version in the status file's `update_available` field. It doesn't download or install anything. A check that fails is logged only at debug level, and rerouted tries again the next day.

## Restart after an upgrade

A restart ends every community voice call on the server. So that an upgrade doesn't cut calls off, rerouted can wait for them to end:

1. Send rerouted `SIGUSR2`. The package's post-install script does this after an upgrade.
2. rerouted logs that a restart is pending, and sets `restart_pending` in the status file. It keeps serving as usual.
3. Every 15 seconds, it checks for active voice calls. Once there are none, it shuts down cleanly and exits with code 75.
4. The service manager starts it again, on the new binary. The packaged systemd units always restart rerouted after exit code 75, and count it as a clean exit rather than a failure (`RestartForceExitStatus=75`, `SuccessExitStatus=75`).

If calls are still going after `REROUTED_RESTART_MAX_WAIT` (6 hours by default), rerouted logs a warning and restarts anyway. Sending `SIGUSR2` again while a restart is pending changes nothing. `SIGTERM`, which `systemctl stop` and `systemctl restart` send, still stops rerouted at once.

If you run rerouted under another service manager, have it restart rerouted when it exits with code 75.

## Database upgrades

A new rerouted version can change the database's schema. Before it changes an existing database, rerouted saves a consistent copy of it beside the database, named for the old schema version, such as `rerouted-v1.db.pre-v10`, and logs the copy's path. It keeps only the newest such copy. If it can't make the copy, it doesn't change the database, and exits with an error.

To go back to the older rerouted after an upgrade:

1. Stop rerouted.
2. Move the database aside, and copy the `.pre-v*` snapshot to `rerouted-v1.db`. Remove `rerouted-v1.db-wal` and `rerouted-v1.db-shm` if they're there.
3. Install the older rerouted, and start it.

Anything stored after the upgrade is lost this way. An older rerouted refuses to open a database a newer one has upgraded, and says which schema version the database has and which one it supports.
