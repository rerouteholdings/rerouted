# Run a homeserver

This guide takes you from a fresh Linux server to a working Tieroute homeserver that people can sign up on with an invite code. You install rerouted from the Reroute package repository, set it up with `rerouted init`, and run it with systemd behind Caddy, which handles TLS.

A *homeserver* holds its users' identities and stores their messages until their devices fetch them. Messages are end-to-end encrypted (E2EE), so the homeserver can route them but never read them.

## Before you begin

You need:

- A Linux server with systemd and a public IP address, on x86_64 (amd64) or arm64. The packages are for Debian 12 or later, Ubuntu 22.04 or later, Fedora, and Arch Linux. These steps use Debian or Ubuntu commands.
- A domain name you control. This guide uses `chat.example`; replace it with yours everywhere.
- Caddy 2.10 or later installed on the server, with nothing else listening on ports 80 and 443. Earlier versions don't offer the hybrid post-quantum key exchange `X25519MLKEM768`, which Tieroute requires servers to offer (SPEC §3). If you set `curves` in a `tls` directive, keep `x25519mlkem768` in it.
- About 20 minutes.

The server's firewall needs TCP ports 80 and 443 open to everyone. Caddy uses port 80 to get certificates from Let's Encrypt.

## Set up DNS

1. Point `chat.example` at your server with an `A` record, and an `AAAA` record if it has IPv6.
2. If you want to give out handles under your domain, such as `@kat.chat.example`, add the same records for `*.chat.example`.

If your DNS provider offers a proxy, such as Cloudflare's, turn it off for these records. The call relay can't work through it.

## Install rerouted

rerouted comes from the same signed repository as the Reroute app. [Install Reroute on Linux](https://rerouteholdings.llc/install/linux) shows the key's fingerprint, and the steps for Fedora and Arch Linux; there, install the `rerouted` package instead of `reroute`.

1. Download the key, and add the repository:

   ```sh
   sudo curl -fsSLo /usr/share/keyrings/reroute-archive-keyring.gpg https://rerouteholdings.llc/reroute/linux/reroute-archive-keyring.gpg
   echo 'deb [signed-by=/usr/share/keyrings/reroute-archive-keyring.gpg] https://rerouteholdings.llc/reroute/linux/apt stable main' | sudo tee /etc/apt/sources.list.d/reroute.list
   ```

2. Install rerouted:

   ```sh
   sudo apt update
   sudo apt install rerouted
   ```

The package installs `/usr/bin/rerouted`, the systemd units, and the manual page, and creates the `rerouted` user. It doesn't start anything yet.

If you installed rerouted by hand before, remove your old copies, so systemd runs the packaged one: `sudo rm /etc/systemd/system/rerouted.service /usr/local/bin/rerouted`, then `sudo systemctl daemon-reload`. Your settings file and data stay where they are.

## Set up rerouted

1. Run `init`, and answer its questions:

   ```sh
   sudo rerouted init
   ```

   It asks for the server's name, `chat.example`, and the domain handles go under. Then it writes `/etc/rerouted/rerouted.env` with a new registration code, creates the data directory in `/var/lib/rerouted` and the server's keys, and prints the DNS records the server needs.
2. Let it add the server to Caddy. Your Caddyfile gains only two `import` lines: rerouted's sites go in their own files in `/etc/caddy/rerouted/`. `init` backs up the Caddyfile first, checks the result with `caddy validate`, and puts everything back if Caddy refuses it. If you install Caddy later, run `sudo rerouted init --caddy-only` to do this step alone.
3. When it offers to enable and start the service, answer yes. Otherwise, start it yourself:

   ```sh
   sudo systemctl enable --now rerouted
   ```

People need the registration code to sign up. It's `REROUTED_REGISTRATION_CODE` in `/etc/rerouted/rerouted.env`. [Settings](settings.md) describes the rest of that file, and [Administer a homeserver](administer-a-homeserver.md#set-up-a-homeserver) describes every `init` option.

## Check that it works

1. Once DNS has spread, run the checkup:

   ```sh
   sudo rerouted checkup
   ```

   Each line says `PASS`, `WARN`, `FAIL`, or `INFO`. A failure names what to fix, such as a DNS record that points somewhere else. If Caddy hasn't got the certificate yet, wait a minute, then run it again. If the server isn't running, read its log with `journalctl -u rerouted -n 50`.
2. In a Tieroute client such as Reroute, create an identity on `chat.example` with your registration code.

## Keep it up to date

New versions of rerouted come with your system's updates: `sudo apt update && sudo apt upgrade`. To have rerouted upgrade itself once a day instead, turn on automatic updates:

```sh
sudo rerouted auto-updates on
```

An upgrade doesn't restart rerouted right away, because a restart ends every community voice call. The package asks rerouted to restart once no voice calls are active, and systemd starts the new version. [Monitoring](monitoring.md#restart-after-an-upgrade) explains how. On Arch Linux, update rerouted with the rest of the system, with `sudo pacman -Syu`.

## Install without the packages

On another Linux system, install the release tarball by hand. You update it yourself, the same way.

1. Download the newest release for your server's CPU (use `ARCH=arm64` for an ARM server), and its signed checksums:

   ```sh
   ARCH=amd64
   VERSION=$(curl -fsS https://rerouteholdings.llc/reroute/linux/rerouted/latest.json | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
   for f in rerouted-$VERSION-linux-$ARCH.tar.gz SHA256SUMS SHA256SUMS.asc; do curl -fsSLO https://rerouteholdings.llc/reroute/linux/rerouted/$VERSION/$f; done
   ```

2. Check the signature and the checksum. The key is the one on [Install Reroute on Linux](https://rerouteholdings.llc/install/linux):

   ```sh
   curl -fsSL https://rerouteholdings.llc/reroute/linux/reroute-archive-keyring.asc | gpg --import
   gpg --verify SHA256SUMS.asc SHA256SUMS
   sha256sum --ignore-missing -c SHA256SUMS
   ```

   `gpg` says `Good signature`, and `sha256sum` prints `OK`. Don't continue otherwise.
3. Install the binary and the systemd units, and create the user rerouted runs as:

   ```sh
   tar -xzf rerouted-$VERSION-linux-$ARCH.tar.gz
   cd rerouted-$VERSION-linux-$ARCH
   sudo install -m 755 rerouted /usr/local/bin/rerouted
   sudo install -m 644 systemd/rerouted.service systemd/rerouted@.service /etc/systemd/system/
   sudo useradd --system --home-dir /var/lib/rerouted --shell /usr/sbin/nologin rerouted
   sudo systemctl daemon-reload
   ```

4. Continue with [Set up rerouted](#set-up-rerouted).

To build rerouted from source instead, see the [README](../README.md#try-it-locally).

## Next steps

- [Run a call relay](run-a-call-relay.md), so your users' calls work without showing each other their IP addresses.
- [Administer a homeserver](administer-a-homeserver.md): back up, handle reports, and control registration.
