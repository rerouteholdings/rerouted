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

3. Optionally, confine rerouted further with your distribution's mandatory access control. The unit already limits what rerouted can do; a profile adds a second, independent check.

   On Debian and Ubuntu, with AppArmor:

   ```sh
   sudo install -m 644 deploy/apparmor/rerouted /etc/apparmor.d/rerouted
   sudo apparmor_parser -r -W /etc/apparmor.d/rerouted
   sudo systemctl restart rerouted
   ```

   On Fedora, RHEL, and their relatives, with SELinux:

   ```sh
   sudo dnf install selinux-policy-devel
   make -f /usr/share/selinux/devel/Makefile -C deploy/selinux rerouted.pp
   sudo semodule -i deploy/selinux/rerouted.pp
   sudo restorecon -R /usr/local/bin/rerouted /etc/rerouted /var/lib/rerouted
   sudo systemctl restart rerouted
   ```

   If `REROUTED_LISTEN` uses a port other than 8080, label it first: `sudo semanage port -a -t rerouted_port_t -p tcp PORT`.

   Check that it took: `ps -eZ | grep rerouted` shows `rerouted_t` under SELinux, and `sudo aa-status` lists `rerouted` under AppArmor.

## Keep the server keys apart

Optionally, move the server keys out of rerouted into rerouted-keyd, a second process that holds them and signs for rerouted. rerouted-keyd has no network and can't write anywhere, and signs only what a server signs with its own key: S2S requests from this server, made now; commit receipts; and move reservations for this server, for 10 minutes. Someone who takes over rerouted can sign only while they're in it, and can't take the keys with them. The keys are kept encrypted with `systemd-creds`, with this machine's credential key, and its TPM if it has one, so a copy of the disk or of a backup doesn't have them. This needs systemd 250 or later.

1. Build `rerouted-keyd` with `rerouted`, then install it and the script that encrypts the keys, and create the user it runs as:

   ```sh
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o rerouted-keyd ./cmd/rerouted-keyd
   ```

   ```sh
   sudo install -m 755 rerouted-keyd /usr/local/bin/rerouted-keyd
   sudo install -D -m 755 deploy/rerouted-keyd-seal /usr/local/libexec/rerouted-keyd-seal
   sudo useradd --system --home-dir /var/lib/rerouted-keyd --shell /usr/sbin/nologin rerouted-keyd
   ```

2. Install the units, and the drop-in that points rerouted at rerouted-keyd:

   ```sh
   sudo install -m 644 deploy/rerouted-keyd.socket deploy/rerouted-keyd.service deploy/rerouted-keyd-seal.service /etc/systemd/system/
   sudo install -D -m 644 deploy/rerouted.service.d/keyd.conf /etc/systemd/system/rerouted.service.d/keyd.conf
   ```

3. With AppArmor, add rerouted-keyd's profile, and load rerouted's again: it allows the socket. With SELinux, the module from the step before already has both, so build and install it again if it's older.

   ```sh
   sudo install -m 644 deploy/apparmor/rerouted deploy/apparmor/rerouted-keyd /etc/apparmor.d/
   sudo apparmor_parser -r -W /etc/apparmor.d/rerouted /etc/apparmor.d/rerouted-keyd
   ```

   ```sh
   sudo restorecon -R /usr/local/bin/rerouted-keyd /usr/local/libexec
   ```

4. Start it, and restart rerouted:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now rerouted-keyd.socket
   sudo systemctl restart rerouted
   ```

   The first time, `rerouted-keyd-seal` moves `server-key.json`, `server-key-v2.json`, and each `community-key-*.json` from `/var/lib/rerouted` into `/var/lib/rerouted-keyd/keys.cred`, encrypted, and deletes them there. The server document lists the same key IDs as before. `journalctl -u rerouted-keyd-seal` says what it moved.

rerouted-keyd restarts with rerouted, and a community added to `REROUTED_COMMUNITIES` gets its key then. Operator commands, such as `reports`, don't need it.

`keys.cred` can only be decrypted on this machine. For a backup that can be restored elsewhere, see [Back up](administer-a-homeserver.md#back-up). To go back to key files in the data directory:

```sh
sudo systemctl stop rerouted
sudo systemctl disable --now rerouted-keyd.socket
sudo systemd-creds decrypt --name=keys /var/lib/rerouted-keyd/keys.cred - | sudo rerouted-keyd unbundle /var/lib/rerouted
sudo chown rerouted:rerouted /var/lib/rerouted/*-key*.json
sudo rm /etc/systemd/system/rerouted.service.d/keyd.conf
sudo systemctl daemon-reload
sudo systemctl start rerouted
```

Turn off the socket first, as here: if rerouted-keyd started again, it would move the key files back.

## Run voice channels apart

If this server hosts communities, its voice channels' SFU takes UDP from anyone and runs WebRTC's parsers on it. Optionally, run it in rerouted-sfu, a process of its own, with no keys, no database, no settings file, and nowhere to write. rerouted sends it the voice settings when it connects. Its unit also keeps it from sending anything to this host or to link-local addresses, so a device's ICE candidates can't point it at local services or a cloud metadata service.

1. Build `rerouted-sfu` with `rerouted`, then install it and create the user it runs as:

   ```sh
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o rerouted-sfu ./cmd/rerouted-sfu
   ```

   ```sh
   sudo install -m 755 rerouted-sfu /usr/local/bin/rerouted-sfu
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin rerouted-sfu
   ```

2. Install the units, and the drop-in that points rerouted at rerouted-sfu:

   ```sh
   sudo install -m 644 deploy/rerouted-sfu.socket deploy/rerouted-sfu.service /etc/systemd/system/
   sudo install -D -m 644 deploy/rerouted.service.d/sfu.conf /etc/systemd/system/rerouted.service.d/sfu.conf
   ```

3. With AppArmor, add rerouted-sfu's profile, and load rerouted's again. With SELinux, the module already has rerouted-sfu's domain: build and install it again if it's older, then label the binary.

   ```sh
   sudo install -m 644 deploy/apparmor/rerouted deploy/apparmor/rerouted-sfu /etc/apparmor.d/
   sudo apparmor_parser -r -W /etc/apparmor.d/rerouted /etc/apparmor.d/rerouted-sfu
   ```

   ```sh
   sudo restorecon /usr/local/bin/rerouted-sfu
   ```

4. Start it, and restart rerouted:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now rerouted-sfu.socket
   sudo systemctl restart rerouted
   ```

   `journalctl -u rerouted-sfu` says `SFU started`. rerouted-sfu stops and starts with rerouted, and everyone in a voice channel is disconnected then, as they are when rerouted restarts without it.

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
