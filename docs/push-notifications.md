# Send push notifications to the Reroute iPhone app

This page explains how to turn on push notifications for the Reroute iPhone app on your homeserver, and what the notifications contain. Push notifications are a feature of Reroute and rerouted. They aren't part of the Tieroute protocol, and other Tieroute servers and clients don't need them.

## How push notifications work

The Reroute app on an iPhone registers its device token with its homeserver. When a delivery for that identity lands in its inbox, rerouted asks Apple's push notification service (APNs) to show a notification on each of the identity's iPhones that has a token and doesn't have the app open.

The notifications are content-free. Every notification says only "New message". It doesn't say who it's from, which chat it's in, or what kind of delivery it was: rerouted can't read messages, which are end-to-end encrypted (E2EE), and it doesn't pass on what it does know. When you open the app, it fetches its deliveries from the homeserver and decrypts them itself.

These deliveries send a notification:

- Messages in direct chats and group chats.
- Being added to a chat.
- Contact requests.

These don't:

- Deliveries from one of the identity's own devices, such as a copy of a message it sent.
- Group changes, such as members joining or leaving.
- Typing notices and read receipts, which are never stored.
- Notices about changes to devices, the identity's own or a contact's.

Calls are signaled inside encrypted messages, so an incoming call shows as "New message" too.

A device gets at most one notification every 10 seconds, and a new notification replaces the one before it. If the app has a live connection to the homeserver, it's in the foreground, and gets no notification. APNs keeps a notification for an iPhone that's offline for about a day.

> **Warning:** Apple learns when your homeserver sends a notification, and to which device token. It never learns who sent the delivery or what's in it.

## Before you begin

You need:

- A running rerouted homeserver. See [Run a homeserver](run-a-homeserver.md).
- An APNs authentication key, a `.p8` file, from the Apple developer account of the team that publishes the app. Only that team's keys can send notifications to the Reroute app.
- The key's 10-character key ID, and the team's 10-character team ID.

To make a key, sign in to the Apple developer account, and in **Certificates, Identifiers & Profiles**, select **Keys**, then add a key with **Apple Push Notifications service (APNs)** turned on. Apple lets you download the `.p8` file only once. Keep a copy somewhere safe.

## Turn on push notifications

1. Copy the `.p8` file to the server, where only the `rerouted` user can read it:

   ```sh
   sudo install -o rerouted -g rerouted -m 600 AuthKey_ABC123DEFG.p8 /etc/rerouted/apns.p8
   ```

2. In the settings file, set the key file and the two IDs:

   ```sh
   REROUTED_APNS_KEY_FILE=/etc/rerouted/apns.p8
   REROUTED_APNS_KEY_ID=ABC123DEFG
   REROUTED_APNS_TEAM_ID=TEAM123456
   ```

   `REROUTED_APNS_TOPIC` is the app's bundle ID. Its default is the Reroute app's, `llc.rerouteholdings.reroute`. Change it only for your own build of the app.

3. Restart rerouted. A reload (`SIGHUP`) doesn't change these settings.

   ```sh
   sudo systemctl restart rerouted
   ```

When it starts, rerouted checks that it can read the key file, that the file holds a PKCS #8 EC P-256 key, and that both IDs are 10 characters. If something is wrong, it doesn't start, and the log says which setting to fix. `rerouted config check` runs the same checks.

## Check that it works

The log has a `push notifications on` line after a restart. With metrics on, `rerouted_push_sent_total` counts the notifications APNs accepted, and `rerouted_push_failed_total` the ones that failed (see [Monitor a homeserver](monitoring.md)). Failures are logged as warnings, with only the first eight characters of the device token.

When APNs says a token no longer works, for example because the app was removed from the iPhone, rerouted deletes the token. It also deletes a device's token when the device is removed from its identity, and all of an identity's tokens when it moves to another homeserver.

## The app's endpoint

This section is for developers of the Reroute app. The endpoint is rerouted's own, outside the Tieroute APIs, and it can change between rerouted releases.

`POST /v0/push/apns` registers the calling device's token. The request needs a client API session of either wire version, in `Authorization: Bearer SESSION_TOKEN`, and a body of type `application/json`:

```json
{"token": "DEVICE_TOKEN_IN_HEX", "env": "production"}
```

`token` is the APNs device token in hex, 32 to 200 characters. `env` is `sandbox` for a development build of the app, or `production` for a TestFlight or App Store build. A device has one token: registering a new one replaces the old one. A token registered by another device or identity moves to the caller.

`DELETE /v0/push/apns` with `{"token": "DEVICE_TOKEN_IN_HEX"}` removes one of the caller's tokens. Removing a token the caller doesn't have isn't an error.

| Status | Error code | When |
|---|---|---|
| `204` | None | Registered or removed. |
| `400` | `bad-request` | The token or `env` isn't valid. |
| `401` | `unauthenticated` | No session, or one that has ended. |
| `403` | `not-allowed` | Registering for an identity that doesn't live on this homeserver. |
| `415` | `bad-content-type` | The body isn't `application/json`. |
| `429` | `rate-limited` | More than 60 requests in an hour from one identity. |
| `501` | `not-implemented` | Push notifications are off on this homeserver. |

Every notification has this payload, with `apns-push-type: alert` and `apns-priority: 10`:

```json
{"aps":{"alert":{"title":"Reroute","body":"New message"},"sound":"default","mutable-content":1,"thread-id":"messages"}}
```

`mutable-content` is set so a Notification Service Extension in the app can change the text.
