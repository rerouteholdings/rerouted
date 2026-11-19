# Run a call relay

This guide adds a call relay to a rerouted homeserver, so your users' calls work behind any network, and neither caller learns the other's IP address.

Tieroute relays calls through each user's own homeserver by default (SPEC §15.1). The relay is a TURN (Traversal Using Relays around NAT) server, such as coturn. rerouted gives your users time-limited credentials for it through `GET turn`. Without a relay, `GET turn` answers `501`, and your users' calls only work if they allow direct connections, which show their IP addresses to each other.

You can use either of two relays:

- The relay built into rerouted. It's the simpler choice: there's nothing else to install, and rerouted makes the shared secret itself. It relays over UDP only, and has no TLS (`turns:`).
- coturn, a separate TURN server. Use it if you want TLS, a relay on another host, or coturn's other options.

## Use the built-in relay

You need:

- A homeserver running as in [Run a homeserver](run-a-homeserver.md).
- A public IP address on the homeserver's host. Clients connect to the relay directly: TURN can't go through an HTTP proxy.

1. In `/etc/rerouted/rerouted.env`, turn the relay on, and give it the host's public IP address:

   ```sh
   REROUTED_TURN_LISTEN=:3478
   REROUTED_TURN_PUBLIC_IP=HOST_IP
   ```

   If `REROUTED_VOICE_PUBLIC_IPS` is already set, you can leave out `REROUTED_TURN_PUBLIC_IP`: the relay uses the first of those addresses. Leave `REROUTED_TURN_URLS` and `REROUTED_TURN_SECRET` unset. rerouted then gives out `turn:` URLs with `REROUTED_NAME` and port 3478, and keeps a random secret in `turn-secret` in its data directory.

2. In the firewall, allow UDP and TCP port 3478, and UDP ports 49160 to 49200 for relayed media. To use other ports, set `REROUTED_TURN_RELAY_PORTS`, such as `REROUTED_TURN_RELAY_PORTS=50000-50100`. Each person in a relayed call uses about two.
3. Make sure `REROUTED_NAME` resolves to `HOST_IP`, since clients reach the relay at that name. If it points somewhere else, such as a proxy on another host, set `REROUTED_TURN_URLS` to `turn:HOST_IP:3478?transport=udp,turn:HOST_IP:3478?transport=tcp`.
4. Restart rerouted:

   ```sh
   sudo systemctl restart rerouted
   ```

   The log says `call relay listening`, with the URLs it gives out.

The built-in relay is set up the way the coturn example below is:

- It takes only the time-limited credentials that `GET turn` gives out.
- It never relays to private, loopback, link-local, multicast, or other non-public addresses, or to the host's own public address outside the relay ports.
- It never relays TCP.
- It allows at most 12 allocations at once for each user, and 200 in all.
- Unlike the coturn example, it doesn't limit bandwidth per session.

To check that it works, see [Check that it works](#check-that-it-works). With metrics on, `rerouted_turn_allocations` counts the relay's open allocations (see [Monitor a homeserver](monitoring.md)).

## Use coturn

### Before you begin

You need:

- A homeserver running as in [Run a homeserver](run-a-homeserver.md).
- A host with a public IP address for the relay. It can be the homeserver's own host. Clients connect to it directly: TURN can't go through an HTTP proxy.
- coturn installed on that host (`sudo apt install coturn` on Debian or Ubuntu).

### Configure coturn

1. Make a shared secret, at least 16 characters long:

   ```sh
   openssl rand -hex 32
   ```

2. Copy [`deploy/turnserver.conf.example`](../deploy/turnserver.conf.example) to `/etc/turnserver.conf`.
3. In `/etc/turnserver.conf`, replace `HOST_IP` with the relay's public IP address, `TURN_SECRET` with the secret from step 1, and `chat.example` with your domain.
4. Restart coturn:

   ```sh
   sudo systemctl restart coturn
   ```

The example is set up for calls and nothing else:

- It gives out only time-limited credentials (`use-auth-secret`).
- It relays media over UDP ports 49160 to 49399, about two per person in a call.
- It refuses to relay to private and loopback addresses (`denied-peer-ip`). Without that, anyone with credentials could use the relay to reach services that only listen inside your network. If the host runs Docker, add its networks too.
- It never relays TCP (`no-tcp-relay`).
- It limits sessions per user, sessions in total, and bandwidth per session.

### Open the firewall

1. Allow UDP and TCP port 3478, for TURN.
2. Allow UDP ports 49160 to 49399, for relayed media.
3. If the relay runs on the homeserver's own host, stop relayed traffic from reaching that host's other services. With `ufw`, where `HOST_IP` is the host's public address:

   ```sh
   sudo ufw deny out proto udp from HOST_IP port 49160:49399 to HOST_IP port 1:49159
   ```

   Relayed traffic can still reach the other relay ports on the host. It needs them when both callers' homeservers use this relay.

### Connect rerouted to the relay

1. In `/etc/rerouted/rerouted.env`, add the relay's address and the same secret:

   ```sh
   REROUTED_TURN_URLS=turn:HOST_IP:3478?transport=udp,turn:HOST_IP:3478?transport=tcp
   REROUTED_TURN_SECRET=TURN_SECRET
   ```

2. Reload rerouted, which applies the relay settings without a restart:

   ```sh
   sudo systemctl reload rerouted
   ```

## Check that it works

`rerouted checkup` tries every URL in `REROUTED_TURN_URLS`, or the built-in relay's. `rerouted backup` includes the built-in relay's generated secret (`turn-secret`).

Sign in from a client and ask for credentials. In Reroute, start a call: it uses the relay when a direct connection isn't allowed. With the client API, `GET turn` with a session token now answers with `urls`, `username`, and `credential` instead of `501`.

If calls still don't connect with coturn, check coturn's log (`journalctl -u coturn`) for refused credentials. The usual cause is a secret that doesn't match `REROUTED_TURN_SECRET`. With the built-in relay, check that the firewall lets the relay ports through, and that `REROUTED_TURN_PUBLIC_IP` is the address clients reach the host at. Setting `REROUTED_LOG_LEVEL=debug` logs refused credentials.
