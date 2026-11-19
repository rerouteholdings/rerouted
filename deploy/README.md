# Deployment examples

These files are starting points for running rerouted on a Linux server. [Run a homeserver](../docs/run-a-homeserver.md) and [Run a call relay](../docs/run-a-call-relay.md) walk through using them.

| File | What it is | Install it as |
|---|---|---|
| `Caddyfile.example` | Caddy in front of rerouted, with certificates on demand for handle subdomains | `/etc/caddy/Caddyfile`, or merged into yours |
| `turnserver.conf.example` | coturn as the call relay, refusing to relay into private networks | `/etc/turnserver.conf` |

The systemd units are in [`packaging/systemd/`](../packaging/systemd/), with the rest of the packaging. The packages install them, and each release tarball includes them (see [Install without the packages](../docs/run-a-homeserver.md#install-without-the-packages)). `rerouted init` writes a Caddy configuration for you, so you only need `Caddyfile.example` to set up Caddy by hand.

Each file here uses `chat.example` as the domain and uppercase placeholders, such as `HOST_IP`, for values you fill in.
