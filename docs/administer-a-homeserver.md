# Administer a homeserver

This guide covers looking after a running rerouted homeserver: what it stores, how to back it up, how to control who signs up, and the admin commands for reports and handles.

## What rerouted stores

Everything lives in the data directory (`REROUTED_DATA_DIR`):

| File | What's in it | Back it up |
|---|---|---|
| `rerouted-v1.db`, with its `-wal` and `-shm` files | The SQLite database: identities, chains, contacts, invite codes (as keyed hashes), inboxes, group hub state, profiles, account data, backups, and reports | Yes |
| `media/` | Files your users uploaded, end-to-end encrypted, and their profile pictures | Yes |
| `server-key.json` | The server's signing key for wire version 1 | Yes |
| `server-key-v2.json` | The server's composite signing key for wire version 2 | Yes |
| `limits.json` | Rate-limit counts, saved every 10 minutes and on shutdown | No: losing it only resets the counts |

Direct chats, group chats, files, and backups are end-to-end encrypted: you can't read them. Metadata isn't: you can see who your users talk to, their contacts and groups, and their presence. Treat it as sensitive.

rerouted upgrades the database to the current schema when it starts. It refuses to open a database written by a newer version, so to go back to an older rerouted, you need a backup from before the upgrade.

## Back up

1. Copy the database with SQLite's online backup. It's consistent even while rerouted runs:

   ```sh
   sqlite3 /var/lib/rerouted/rerouted-v1.db ".backup /backups/rerouted-v1.db"
   ```

2. Copy `media/`, `server-key.json`, and `server-key-v2.json` to the same place.

Keep both key files safe. If you lose one, rerouted makes a new key, and other servers pick it up from the server document, but if you lose `server-key.json`, every invite code your users made stops working. Codes are keyed with a secret derived from that key (SPEC §9.1).

> Caution: **Never restore an old database over a running server.** Groups whose hub is this server stop accepting changes, because the restored hub holds old epoch keys, and their members have to re-create them (SPEC §11.6). Inboxes and chains go back to an older state too. Restore a backup only to replace a server that's gone permanently.

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
| `rerouted -env /etc/rerouted/rerouted.env reports [N]` | Prints the N newest reports, 20 by default. |
| `rerouted -env /etc/rerouted/rerouted.env remove-media ID --confirm` | Deletes a reported file. Fetches of it then answer `410 removed`. |
| `rerouted -env /etc/rerouted/rerouted.env release-handle HANDLE --confirm` | Frees a handle so a new identity can register it. The old identity keeps its chain, but the handle no longer resolves to it, so clients show the handle as no longer valid (SPEC §5.3). It also ends a handle's 30-day hold early, or undoes `keep-handle`. |
| `rerouted -env /etc/rerouted/rerouted.env keep-handle HANDLE` | Keeps a handle reserved for the identity that holds it, instead of freeing it when its 30-day hold ends (below). Nobody else can register it until you run `release-handle`. |

When someone changes their handle, or moves to another homeserver, rerouted holds the old name for them for 30 days (SPEC §5.3). During the hold nobody else can register it or move here with it, and it resolves as no longer valid, so their contacts have time to see the change. The person can take the name back. After 30 days rerouted frees it. Use `keep-handle` for a name you'd rather nobody took, for example one that's easy to confuse with another.

Run them as the `rerouted` user, so the files they touch keep the right owner: `sudo -u rerouted rerouted -env …`.

## Pause moves

An identity can move from one homeserver to another (SPEC §6.6). If a client's move flow is known to be unsafe, you can refuse moves until it's fixed:

1. In the settings file, set `REROUTED_PAUSE_MOVES=on`.
2. Restart rerouted.

Device-signed moves to and from this server then fail before anything changes, with `403 not-allowed` and a message saying moving is paused. The identity stays where it is. Recovery-signed entries still go through, so recovery codes keep working.

## Set storage quotas

Each identity may store `REROUTED_MEDIA_QUOTA` bytes of files and `REROUTED_BACKUP_QUOTA` bytes of backups, 1 GiB each by default. Uploads over a quota get `413 over-quota`. Files are deleted 30 days after upload, so the file quota limits what someone can have stored at once. Size the disk for your number of users times the two quotas, or lower them.
