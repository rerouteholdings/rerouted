# Run a homeserver

This guide takes you from a fresh Linux server to a working Tieroute homeserver that people can sign up on with an invite code. It uses systemd to run rerouted and Caddy for TLS, with the example files in [`deploy/`](../deploy/).

A *homeserver* holds its users' identities and stores their messages until their devices fetch them. Messages are end-to-end encrypted (E2EE), so the homeserver can route them but never read them.

## Before you begin

You need:

- A Linux server with systemd and a public IP address. These steps use Debian or Ubuntu commands.
- A domain name you control. This guide uses `chat.example`; replace it with yours everywhere.
- Caddy 2 installed on the server, with nothing else listening on ports 80 and 443.
- Go on the machine you build on, at the version in [`go.mod`](../go.mod).
- About 30 minutes.

The server's firewall needs TCP ports 80 and 443 open to everyone. Caddy uses port 80 to get certificates from Let's Encrypt.

## Set up DNS

1. Point `chat.example` at your server with an `A` record, and an `AAAA` record if it has IPv6.
2. If you want to give out handles under your domain, such as `@kat.chat.example`, add the same records for `*.chat.example`.

If your DNS provider offers a proxy, such as Cloudflare's, turn it off for these records. The call relay can't work through it.

## Build and install rerouted

1. On your build machine, build a static binary for the server's CPU. Use `GOARCH=arm64` for an ARM server:

   ```sh
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o rerouted ./cmd/rerouted
   ```

2. Copy `rerouted`, `.env.example`, and the `deploy/` directory to the server.
3. On the server, install the binary and create the user it runs as:

   ```sh
   sudo install -m 755 rerouted /usr/local/bin/rerouted
   sudo useradd --system --home-dir /var/lib/rerouted --shell /usr/sbin/nologin rerouted
   ```

## Configure rerouted

1. Create the settings file from the example:

   ```sh
   sudo install -d -m 750 -g rerouted /etc/rerouted
   sudo install -m 640 -g rerouted .env.example /etc/rerouted/rerouted.env
   ```

2. Make a registration code. People need it to sign up:

   ```sh
   openssl rand -hex 12
   ```

3. In `/etc/rerouted/rerouted.env`, set these, with your domain and the code from step 2:

   ```sh
   REROUTED_NAME=chat.example
   REROUTED_HANDLES=chat.example
   REROUTED_DATA_DIR=/var/lib/rerouted
   REROUTED_REGISTRATION=invite
   REROUTED_REGISTRATION_CODE=YOUR_CODE
   ```

   Leave out `REROUTED_HANDLES` if you skipped the wildcard DNS records. [Settings](settings.md) describes the rest.

## Start rerouted

1. Install the systemd unit, then start rerouted:

   ```sh
   sudo install -m 644 deploy/rerouted.service /etc/systemd/system/rerouted.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now rerouted
   ```

2. Check that it answers on the server itself:

   ```sh
   curl -s http://127.0.0.1:8080/.well-known/tieroute/server
   ```

   It prints the server document, a JSON object that starts with `{"apis":`. If it prints nothing, read the log with `journalctl -u rerouted -n 50`. A setting it can't use is named there.

## Put Caddy in front

1. Copy [`deploy/Caddyfile.example`](../deploy/Caddyfile.example) to `/etc/caddy/Caddyfile`, and replace every `chat.example` with your domain. If Caddy already serves other sites, add its blocks to your Caddyfile instead, and put the `on_demand_tls` option in your global options block.
2. Check the configuration, then reload Caddy:

   ```sh
   sudo caddy validate --config /etc/caddy/Caddyfile
   sudo systemctl reload caddy
   ```

Caddy gets a certificate for `chat.example` right away. Handle subdomains get one the first time someone looks them up, and only after rerouted confirms that the handle exists, so random names can't use up your Let's Encrypt rate limits.

## Check that it works

1. From any other machine, fetch the server document:

   ```sh
   curl -s https://chat.example/.well-known/tieroute/server
   ```

   It prints the same JSON object as before, with `"name":"chat.example"`. If `curl` reports a certificate error, wait a minute for Caddy to get the certificate, then try again.
2. In a Tieroute client such as Reroute, create an identity on `chat.example` with your registration code.

## Next steps

- [Run a call relay](run-a-call-relay.md), so your users' calls work without showing each other their IP addresses.
- [Administer a homeserver](administer-a-homeserver.md): back up, handle reports, and control registration.
