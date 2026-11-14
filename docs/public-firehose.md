# Public firehose

The public firehose is a live feed of every delivery this server stores in a local user's inbox, for showing the protocol at work on a public development server. It isn't part of Tieroute, and other servers don't need it.

This page describes what it sends, and what it costs your users in privacy.

## Turn it on

It's off by default. Set `REROUTED_PUBLIC_FIREHOSE=on` to turn it on. When it's off, `GET /v0/dev/firehose` answers `404 not-found`, like any unknown path.

> Warning: **The feed never shows a delivery's contents, but anyone can see its metadata:** who sent what kind of delivery to whom, its epoch, its size, and when. Only turn it on for a server whose users have agreed to that.

## What it sends

`GET /v0/dev/firehose` needs no authentication and answers with Server-Sent Events (`text/event-stream`). Each delivery is one event:

```text
event: delivery
data: {"n":1,"ts":"2026-11-09T14:25:00Z","for":"kat.example.com","from":"ravi.example.com","delivery":{...}}

```

- `n`: a sequence number, starting at 1 each time the server starts.
- `ts`: when the item was stored, in UTC.
- `for`: the recipient's handle, or their identifier (`tr:…`) if they have no handle that resolves both ways.
- `from`: the sender's handle, or their identifier if their handle doesn't resolve both ways. It's left out if the delivery has no sender.
- `delivery`: the delivery as stored, censored. `data` is replaced by its size in bytes (`data_bytes`), so no ciphertext, link bundle, or chain entries leave the server. `group` and `receipt` are left out, so a group's messages can't be linked together. `id` is replaced by a 16-character hash, keyed with a secret that changes each time the server starts: the copies of one delivery share a hash, but it can't be matched to the real ID. Everything else is as `GET inbox` returns it.

## Handles

A handle is shown only if it resolves both ways (SPEC §5.3). A handle registered here is checked against this server's own index, and any other by fetching its handle document. Those checks are kept for 10 minutes, failures included.

## Connections

A new connection first gets the last 50 events, which are kept only in memory, and then live ones. A `: ping` comment comes every 25 seconds, so proxies keep the connection open. The server allows 200 connections at once, and answers `503 unavailable` beyond that. A connection that falls 64 events behind is closed, so a slow reader never delays delivery.
