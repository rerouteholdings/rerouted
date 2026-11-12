# How rerouted stores moves and recovery wraps

Two parts of the spec change several records at once: an identity moving between homeservers (SPEC §6.6), and the wrapped account keys that recovery codes open (SPEC §6.3). This page explains how rerouted keeps each one consistent, for implementers comparing notes and for anyone changing that code. It describes rerouted, not the protocol: other servers may do it differently.

## Moves

An *identity* moves by appending a move entry to its chain on its old homeserver, then registering the whole chain on the new one.

### Registering a move here

A move registration commits the complete chain, the handle, the identity's initial allowlists, and the acceptance receipt in one database transaction. Either all of it is stored, or none of it is.

A retry of the same signed move, even with a fresh timestamp, changes nothing. In particular, it doesn't import the allowlists again.

### Reservations

Before a client moves, it asks the new homeserver whether it will take the identity (`POST register` with `"check": true`). rerouted then stores a *reservation* and answers with a `move-reservation` signed by its server key, valid for 10 minutes.

- As the old homeserver, rerouted appends a device-signed move away only with a valid reservation from the destination. It checks the reservation before anything changes. A client without one gets `403 not-allowed`, and its identity stays where it is.
- A reservation holds its handle against other identities until the identity registers, or for 30 days after the reservation expires. Maintenance then deletes it.
- A registration never needs a reservation, so a late registration of a move that was already appended still works.

This isn't a distributed transaction. If the destination disappears after the old homeserver appends the move, the identity waits for the destination to come back, or for its owner to use the recovery code.

### Return moves

An identity can move back to a homeserver it left. Registering a return can extend this server's old tombstone for the identity. In the same transaction, it deletes the account data, backups, and key wraps left from the identity's earlier stay here. Recovery wraps stay.

## Recovery wraps

A *recovery wrap* is the identity's account key, encrypted under a key derived from a recovery code (SPEC §6.3). Changing the recovery code first stages a wrap for the new code, then promotes it once the chain commits to that code. rerouted decides each promotion and cleanup in the same transaction as the chain write that triggers it.

- A promotion has to name a code the chain commits to, and no older than the current one.
- Cleanup keeps a staged wrap the chain commits to until it's promoted. It keeps a staged wrap the chain doesn't mention for 24 hours.
- A wrap that a promotion replaces is retained: it's no longer listed, but it isn't deleted either. While it's kept, the old recovery code still opens the account key.
- An identity can have at most 32 staged and retained wraps, and at most 8 staged at once. At the limit, staging another gets `429 rate-limited`.
- A device can ask to forget retained wraps (`remove: "retained"`). Only wraps for codes the chain has replaced are deleted, never the current one or a staged one, and only 72 hours after the chain entry that made the current code current. Before then, the request gets `429 rate-limited` with `retry`.
