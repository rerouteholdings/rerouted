# Deployment examples

These files are starting points for running rerouted on a Linux server. [Run a homeserver](../docs/run-a-homeserver.md) and [Run a call relay](../docs/run-a-call-relay.md) walk through using them.

| File | What it is | Install it as |
|---|---|---|
| `rerouted.service` | A systemd unit for one rerouted instance, locked down to its own data directory and the network | `/etc/systemd/system/rerouted.service` |
| `Caddyfile.example` | Caddy in front of rerouted, with certificates on demand for handle subdomains | `/etc/caddy/Caddyfile`, or merged into yours |
| `turnserver.conf.example` | coturn as the call relay, refusing to relay into private networks | `/etc/turnserver.conf` |

Each one uses `chat.example` as the domain and uppercase placeholders, such as `HOST_IP`, for values you fill in.
