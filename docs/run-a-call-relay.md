# Run a call relay

This guide adds a call relay to a rerouted homeserver, so your users' calls work behind any network, and neither caller learns the other's IP address.

Tieroute relays calls through each user's own homeserver by default (SPEC §15.1). The relay is a TURN (Traversal Using Relays around NAT) server, such as coturn. rerouted gives your users time-limited credentials for it through `GET turn`. Without a relay, `GET turn` answers `501`, and your users' calls only work if they allow direct connections, which show their IP addresses to each other.

## Before you begin

You need:

- A homeserver running as in [Run a homeserver](run-a-homeserver.md).
- A host with a public IP address for the relay. It can be the homeserver's own host. Clients connect to it directly: TURN can't go through an HTTP proxy.
- coturn installed on that host (`sudo apt install coturn` on Debian or Ubuntu).

## Configure coturn

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

## Open the firewall

1. Allow UDP and TCP port 3478, for TURN.
2. Allow UDP ports 49160 to 49399, for relayed media.
3. If the relay runs on the homeserver's own host, stop relayed traffic from reaching that host's other services. With ufw, where `HOST_IP` is the host's public address:

   ```sh
   sudo ufw deny out proto udp from HOST_IP port 49160:49399 to HOST_IP port 1:49159
   ```

   Relayed traffic can still reach the other relay ports on the host. It needs them when both callers' homeservers use this relay.

## Connect rerouted to the relay

1. In `/etc/rerouted/rerouted.env`, add the relay's address and the same secret:

   ```sh
   REROUTED_TURN_URLS=turn:HOST_IP:3478?transport=udp,turn:HOST_IP:3478?transport=tcp
   REROUTED_TURN_SECRET=TURN_SECRET
   ```

2. Restart rerouted:

   ```sh
   sudo systemctl restart rerouted
   ```

## Check that it works

Sign in from a client and ask for credentials. In Reroute, start a call: it uses the relay when a direct connection isn't allowed. With the client API, `GET turn` with a session token now answers with `urls`, `username`, and `credential` instead of `501`.

If calls still don't connect, check coturn's log (`journalctl -u coturn`) for refused credentials. The usual cause is a secret that doesn't match `REROUTED_TURN_SECRET`.
