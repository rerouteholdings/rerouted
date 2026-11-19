# Administer a homeserver

This guide covers setting up and looking after a rerouted homeserver: the `rerouted` commands that set it up and check it, what it stores, how to back it up and restore it, how to control who signs up, and the admin commands for identities, reports, and handles. `rerouted help` lists every command, and `man rerouted` describes them too.

## Find the settings file

Every command reads the same settings file as the server. Without `-env FILE`, rerouted uses the first of these that exists:

1. `.env` in the working directory.
2. `/etc/rerouted/rerouted.env`, where the packages put it.

If neither exists, settings come from the environment only. A file named with `-env` must exist, so a typo in its name stops the command instead of running with no settings. The examples below use the packaged location, so they leave out `-env`.

Commands that read the data directory need the user rerouted runs as, or root: `sudo -u rerouted rerouted status`. Commands that change files there, such as `restore`, need the same user, so the files keep the right owner.

## Set up a homeserver

`rerouted init` sets up a new homeserver. It asks for the server name and the domain handles go under, then:

1. Picks a free local port, and generates a registration code.
2. Writes the settings file. It never overwrites one: if the file exists, it stops and says so.
3. Creates the data directory and the server's keys.
4. Prints the DNS records to add: A and AAAA records for the name and for `*.HANDLE_DOMAIN`. Handles on this server need no TXT records, because rerouted serves their HTTPS handle documents (SPEC §5.3).
5. Adds the server's sites to Caddy, if Caddy is installed (below).
6. Offers to turn on automatic updates, and to enable and start the systemd service. Both default to no.

As root, the settings file is `/etc/rerouted/rerouted.env`, with data in `/var/lib/rerouted`, run by `rerouted.service`. If that file already exists, `init` sets up a second instance: `/etc/rerouted/NAME.env`, with data in `/var/lib/rerouted-NAME`, run by `rerouted@NAME.service`. As another user, it writes `./.env`, with data in `./data`.

To run it without questions, give the answers as flags:

```sh
sudo rerouted init --yes --name chat.example --registration invite
```

| Flag | What it sets |
|---|---|
| `--name NAME` | The server's DNS name. Required with `--yes`. |
| `--handles DOMAIN` | The domain handles go under, so users get `@kat.DOMAIN`. Default: the name. |
| `--listen HOST:PORT` | The local address rerouted listens on. Default: the first free port from 8080 on 127.0.0.1. |
| `--data-dir DIR` | The data directory. |
| `--registration invite\|public\|closed` | Who can sign up: people you give the code, anyone, or nobody. Default: invite. |
| `--env FILE` | The settings file to write. |
| `--yes` | Asks nothing: takes the flags and the defaults. |
| `--no-caddy` | Leaves Caddy alone. |
| `--caddy-only` | Only adds an existing settings file's sites to Caddy. |
| `--auto-updates` | Turns on automatic updates. |
| `--start` | Enables and starts the systemd service. |

When it's done, and DNS has spread, run `rerouted checkup`.

### How init changes Caddy

If `caddy` is on the path and `/etc/caddy/Caddyfile` exists, `init` adds the server's sites to Caddy without replacing anything you wrote:

- The sites go in a file of their own, `/etc/caddy/rerouted/NAME.caddy`: the server's APIs on its name, and handle documents on the handle wildcard, whose certificates Caddy gets on demand. If that file already exists with other contents, `init` keeps it, writes `NAME.caddy.new` beside it, and asks you to compare them.
- Before getting a certificate for a handle, Caddy asks rerouted whether the handle exists, so random subdomains can't use up the certificate authority's rate limits. Caddy only accepts that `on_demand_tls` setting in its global options block, so `init` puts it in `/etc/caddy/rerouted/global/NAME.caddy`.
- The Caddyfile gains two lines, and only if it doesn't have them yet: `import /etc/caddy/rerouted/global/*.caddy` inside the global options block (`init` adds the block at the top if there's none), and `import /etc/caddy/rerouted/*.caddy` at the end. Before editing, `init` copies the Caddyfile to `Caddyfile.bak-rerouted-TIME`. The edit keeps the file's mode and owner.
- It runs `caddy validate`. If that fails, it restores the Caddyfile, removes the files it added, prints Caddy's error, and exits with an error. If it passes, it reloads Caddy.

Two cases change this:

- If Caddy's global options already have an `on_demand_tls`, for example from another rerouted on the same machine, `init` doesn't add a second one: Caddy takes one ask URL. Instead, it tells you to add this instance's address to `REROUTED_TLS_ASK_ALSO` in the settings of the rerouted that the existing ask points at. That rerouted then asks this one about handles it doesn't know.
- If the Caddyfile says a tool generates or manages it, `init` doesn't edit it. It writes its two files and prints the two import lines, for you to add to whatever generates the Caddyfile.

Changing Caddy needs root. As another user, `init` writes nothing under `/etc/caddy`, and prints the command to run later: `sudo rerouted init --caddy-only --env FILE`.

## Check a homeserver

| Command | What it checks |
|---|---|
| `rerouted config check` | The settings file. |
| `rerouted checkup` | The settings, and the server as other servers and clients reach it. |
| `rerouted status` | Whether the server is running, and what it holds. |

### Check the settings

`rerouted config check` reports what would stop rerouted from starting, such as a missing `REROUTED_NAME`, a listen address that isn't `host:port`, a data directory it can't write to, or `REROUTED_TURN_URLS` without `REROUTED_TURN_SECRET`. It also warns about settings that aren't rerouted's, which are usually typos, and suggests the setting you probably meant. It exits with status 1 if there's an error. Run it after every change to the settings file.

### Check the server

`rerouted checkup` prints a line for each check, marked `PASS`, `WARN`, `FAIL`, or `INFO`, and exits with status 1 if any check fails:

| Check | Fails or warns when |
|---|---|
| `config` | The settings have an error (fail) or a likely mistake (warn), as `config check` reports. |
| `disk` | Less than 200 MiB is free on the data directory's disk (fail), or less than 1 GiB (warn). |
| `listener` | Nothing answers with this server's document on `REROUTED_LISTEN` (fail). |
| `dns` | The name doesn't resolve, or one of its addresses doesn't reach this server over HTTPS (fail). Each A and AAAA record is checked separately, by comparing the keys in the document it serves with the local listener's, so a stale record shows up. Without a wildcard record for handles, it warns. |
| `https` | The server document isn't served at `REROUTED_PUBLIC_URL`, or the proxy reaches another rerouted (fail). |
| `certificate` | The certificate expires in less than 14 days (warn). Caddy renews at 30 days, so this means renewal is failing. |
| `clock` | This machine's clock is more than 30 s off the time in the HTTPS `Date` header (warn), or more than 5 minutes (fail): other servers refuse signatures that far off (SPEC §8.4). |
| `ntp` | systemd says the clock isn't synchronized (warn). |
| `handles` | With `--handle HANDLE`, the handle's certificate or handle document is missing (warn). |
| `turn` | A call relay URL in `REROUTED_TURN_URLS` doesn't answer: a STUN request over UDP, a TCP connection, or a TLS handshake for `turns:` (fail). |
| `voice` | Never fails: checkup can't test the community voice UDP port from inside, so it reminds you to open it. |
| `federation` | With `--peer NAME`, that server's document can't be fetched, or its clock is more than 5 minutes off (fail). |

Checkup asks no outside service for this machine's address. It reaches its own name over HTTPS instead, so it works behind NAT and proxies.

```sh
rerouted checkup --peer example.org --handle kat.chat.example
```

### See whether it's running

`rerouted status` shows whether the server is running, how long it's been up, its version, active voice calls, requests waiting for other servers, a pending restart, and an available update. Then it counts the identities, devices, and communities in the database, and its size.

It reads `status.json` in the data directory, which the running server rewrites regularly and removes when it stops. If the file is missing or more than 90 s old, the server counts as not running. If the running server is an older version than the `rerouted` binary, for example after a package update, `status` says a restart is due. `status --json` prints the same as JSON, for scripts.

`status` opens the database read-only. It never upgrades it, so it's safe to run a newer binary beside an older running server.

## What rerouted stores

Everything lives in the data directory (`REROUTED_DATA_DIR`):

| File | What's in it | Back it up |
|---|---|---|
| `rerouted-v1.db`, with its `-wal` and `-shm` files | The SQLite database: identities, chains, contacts, invite codes (as keyed hashes), inboxes, group hub state, profiles, account data, backups, and reports | Yes |
| `media/` | Files your users uploaded, end-to-end encrypted, and their profile pictures | Yes |
| `server-key.json` | The server's signing key for wire version 1 | Yes |
| `server-key-v2.json` | The server's composite signing key for wire version 2 | Yes |
| `turn-secret` | The built-in call relay's secret, if `REROUTED_TURN_LISTEN` is set and `REROUTED_TURN_SECRET` isn't | Yes |
| `limits.json` | Rate-limit counts, saved every 10 minutes and on shutdown | No: losing it only resets the counts |
| `status.json` | The running server's status, for `rerouted status` | No: the server rewrites it |

Direct chats, group chats, files, and backups are end-to-end encrypted: you can't read them. Metadata isn't: you can see who your users talk to, their contacts and groups, and their presence. Treat it as sensitive.

rerouted upgrades the database to the current schema when it starts. It refuses to open a database written by a newer version, so to go back to an older rerouted, you need a backup from before the upgrade.

## Back up and restore

`rerouted backup` writes one archive with everything the server needs: a consistent copy of the database, the key files, the call relay's secret if it has one, `media/`, and the settings file. It works while the server runs.

```sh
sudo -u rerouted rerouted backup /backups
```

The archive is `rerouted-backup-NAME-TIME.tar.gz`, readable only by the user who made it. Give a directory, or a file name ending in `.tar.gz`. The default is the working directory. It leaves out `status.json` and `limits.json`, which only matter to a running process.

> Warning: **The archive holds the server's private keys and settings.** Keep it as safe as the server itself.

Keep backups of both key files. If you lose one, rerouted makes a new key, and other servers pick it up from the server document. Losing `server-key.json` also breaks every invite code your users made, because codes are keyed with a secret derived from that key (SPEC §9.1).

To restore a backup, stop rerouted, then run `restore` as the user rerouted runs as:

```sh
sudo systemctl stop rerouted
sudo -u rerouted rerouted restore /backups/rerouted-backup-chat.example-20261118T120000Z.tar.gz
sudo systemctl start rerouted
```

`restore` refuses to run while the server is running. It also refuses if the data directory already has a database, unless you add `--force`. With `--force`, it first moves the current data to `before-restore-TIME` inside the data directory. It unpacks the archive completely before changing anything, so a damaged archive leaves the data as it was. It doesn't change your settings file: the archive's copy stays in the archive, as `settings.env`.

> Caution: **Never restore an old database over a server that's still in use.** Groups whose hub is this server stop accepting changes, because the restored hub holds old epoch keys, and their members have to re-create them (SPEC §11.6). Inboxes and chains go back to an older state too. Restore a backup only to replace a server that's gone permanently, or one that hasn't been used since the backup.

`restore` also refuses a backup whose database a newer rerouted wrote, as rerouted itself does (above).

## Control who signs up

Registration is by invite code (SPEC §8.2):

- To let people sign up with a code you give them, set `REROUTED_REGISTRATION=invite` and `REROUTED_REGISTRATION_CODE` to a code of at least 10 characters.
- To let anyone sign up, also set `REROUTED_REGISTRATION_PUBLIC=on`. That publishes the code in the server document.
- To close registration, change the code, or set `REROUTED_REGISTRATION=closed`.

Restart rerouted after changing any of these. Identities that already exist aren't affected.

## Run admin commands

Run these on the server, with the same settings file as rerouted. They work while it runs.

| Command | What it does |
|---|---|
| `rerouted accounts [N]` | Lists the N newest identities whose chains this server stores, 50 by default: when each was created, its handle, its number of devices, its wire version, and its identifier. Identities that moved to another homeserver, or migrated to wire version 2, are marked. |
| `rerouted communities` | Lists the community servers this server hosts (`REROUTED_COMMUNITIES`), with member counts. Names that have no community yet are marked. |
| `rerouted reports [N]` | Prints the N newest reports, 20 by default. |
| `rerouted remove-media ID --confirm` | Deletes a reported file. Fetches of it then answer `410 removed`. |
| `rerouted release-handle HANDLE --confirm` | Frees a handle so a new identity can register it. The old identity keeps its chain, but the handle no longer resolves to it, so clients show the handle as no longer valid (SPEC §5.3). It also ends a handle's 30-day hold early, or undoes `keep-handle`. |
| `rerouted keep-handle HANDLE` | Keeps a handle reserved for the identity that holds it, instead of freeing it when its 30-day hold ends (below). Nobody else can register it until you run `release-handle`. |

When someone changes their handle, or moves to another homeserver, rerouted holds the old name for them for 30 days (SPEC §5.3). During the hold nobody else can register it, move here with it, or rename to it (they get `409 handle-taken`), and it resolves as no longer valid, so their contacts have time to see the change. The person can take the name back. After 30 days rerouted frees it. Use `keep-handle` for a name you'd rather nobody took, for example one that's easy to confuse with another.

`accounts` and `communities` only read the database. Run all of them as the `rerouted` user, so the files they touch keep the right owner: `sudo -u rerouted rerouted reports`.

## Pause moves

An identity can move from one homeserver to another (SPEC §6.6). If a client's move flow is known to be unsafe, you can refuse moves until it's fixed:

1. In the settings file, set `REROUTED_PAUSE_MOVES=on`.
2. Restart rerouted.

Device-signed moves to and from this server then fail before anything changes, with `403 not-allowed` and a message saying moving is paused. The identity stays where it is. Recovery-signed entries still go through, so recovery codes keep working.

## Set storage quotas

Each identity may store `REROUTED_MEDIA_QUOTA` bytes of files and `REROUTED_BACKUP_QUOTA` bytes of backups, 1 GiB each by default. Uploads over a quota get `413 over-quota`. Files are deleted 30 days after upload, so the file quota limits what someone can have stored at once. Size the disk for your number of users times the two quotas, or lower them.

## Turn on automatic updates

If you installed rerouted from the Reroute package repository, it can update itself daily:

```sh
sudo rerouted auto-updates on
```

This turns on `rerouted-update.timer`, which comes with the package. Once a day, it upgrades the rerouted package alone, and rerouted restarts once no calls are active. `rerouted auto-updates status` shows whether it's on, and when it last ran. `rerouted auto-updates off` turns it off.

It only works for the package:

- It refuses if the running binary isn't `/usr/bin/rerouted`, or if no package owns that file (checked with `dpkg` or `rpm`).
- It isn't available on Arch Linux and its derivatives: pacman doesn't support upgrading one package alone, so update rerouted with the rest of the system, with `pacman -Syu`.
- It isn't available on Gentoo. Update rerouted with the rest of the system.

## Install shell completion and the manual page

`rerouted completion bash`, `zsh`, or `fish` prints a completion script. For example, for bash:

```sh
rerouted completion bash | sudo tee /etc/bash_completion.d/rerouted > /dev/null
```

The manual page is `docs/rerouted.1` in the source. The packages install it, so `man rerouted` works. `rerouted version` prints the version, the Go version and platform it was built with, the database schema version, and the wire versions it speaks.
