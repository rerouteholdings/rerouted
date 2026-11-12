// Package store defines the storage rerouted needs. Its implementation is in
// internal/store/sqlite.
package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

var (
	ErrNotFound    = errors.New("store: not found")
	ErrConflict    = errors.New("store: conflict") // stale head, already exists, etc.
	ErrOverQuota   = errors.New("store: over quota")
	ErrHandleTaken = errors.New("store: handle taken")
	// ErrExists is a write that conflicts with what's stored under the same key, as
	// opposed to ErrConflict, a write based on a stale version.
	ErrExists = errors.New("store: exists with different content")
)

// Store is everything a homeserver keeps.
type Store interface {
	Chains() Chains
	Sessions() Sessions
	KeyPackages() KeyPackages
	Contacts() Contacts
	Invites() Invites
	Inbox() Inbox
	Hub() Hub
	Remote() Remote
	Outbox() Outbox
	Sent() Sent
	Profiles() Profiles
	Media() Media
	Account() Account
	Backups() Backups
	Reports() Reports
	Close() error
}

// Chains stores identity chains for local users (SPEC §6.5).
type Chains interface {
	// RegisterMove atomically installs a verified complete chain and replaces initial
	// allowlists. Expected is the exact local chain checked by the caller (nil for
	// first arrival). An accepted intent is a permanent no-op on retry.
	// Returns true only when a new registration was committed, never on a retry.
	// Check performs the same local checks without registering anything; with Reserve,
	// it then stores that reservation (or refreshes the one with the same ID and Entry)
	// in the same transaction, and returns true. A retry of an accepted intent returns
	// false with no reservation.
	RegisterMove(ctx context.Context, m MoveRegistration) (bool, error)
	// Create stores a new identity's genesis entry. ErrConflict if the ID exists with other bytes.
	Create(ctx context.Context, id string, genesis []byte, handle string) error
	// Append adds an entry if prevSeq is still the head. ErrConflict if not (stale-head).
	Append(ctx context.Context, id string, prevSeq uint64, entry []byte) error
	// Fork replaces the entries with seq >= from by `entries` (a recovery fork, SPEC §6.4.1).
	// ErrConflict if the head isn't headSeq anymore.
	Fork(ctx context.Context, id string, from, headSeq uint64, entries [][]byte) error
	// Entries returns encoded entries with seq > after, in order.
	Entries(ctx context.Context, id string, after int64) ([][]byte, error)
	// ByHandle finds the local identity holding a handle.
	ByHandle(ctx context.Context, handle string) (id string, err error)
	// ReleaseHandle frees a handle, so a new identity can register it, and returns the
	// identity that held it. ErrNotFound if nobody does. The old identity's chain still
	// names the handle, but it no longer resolves to it, so clients show "handle no longer
	// valid" (SPEC §5.3). An operator action, not a protocol one.
	ReleaseHandle(ctx context.Context, handle string) (id string, err error)
	// Reservations lists an identity's stored reservations.
	Reservations(ctx context.Context, id string) ([]MoveReservation, error)
	// PruneReservations deletes reservations whose hold ended before `now`. Registration
	// never needs one, so this can't strand a move the old home appended.
	PruneReservations(ctx context.Context, now int64) (int, error)
}

// MoveReservation is a destination's record of a device-signed move it agreed to take
// (SPEC §6.6). While it's stored and Hold hasn't passed, Handle is held for ID: Create and
// RegisterMove (checks and reservations included) refuse it to any other identity with
// ErrHandleTaken. A committed RegisterMove for ID deletes all of ID's reservations in the
// same transaction.
type MoveReservation struct {
	ID     string
	Entry  []byte // SHA-256 of the move entry, the hash the chain uses
	Handle string
	Exp    int64 // the signed reservation's exp
	Hold   int64 // when the handle hold ends: Exp + 30 days
}

type MoveRegistration struct {
	ID, Handle string
	Operation  []byte // canonical MoveIntent (no timestamp or signature)
	// Expected non-empty is a return migration: the identity's own local tombstone, which
	// Entries strictly extends. Committing one also clears the identity's account data,
	// backups, and every key slot but recovery wraps (IsRecoverySlot) left from its earlier
	// stay, in the same transaction (SPEC §6.6, proposed). A retry is a receipt no-op, so it
	// never clears what was written after the registration was accepted.
	Expected, Entries [][]byte
	Contacts          []Contact
	Groups            [][]byte
	Check             bool
	// Probe checks receipts and exact legacy completion only; otherwise ErrNotFound.
	Probe bool
	// Reserve, with Check: the reservation to store if every check passes (SPEC §6.6).
	Reserve *MoveReservation
}

// IsRecoverySlot reports whether an account key slot holds a recovery wrap: the current
// one, a staged one, or a retained one (SPEC §6.3). A return migration keeps these.
func IsRecoverySlot(slot string) bool {
	return slot == "recovery" || strings.HasPrefix(slot, "recovery-next") || strings.HasPrefix(slot, "recovery-retained/")
}

// MoveMatches rechecks the caller's local-state observation and requires a
// strict extension. Return eligibility and signatures are checked before storage;
// matching every observed byte here keeps those checks valid at commit time.
func MoveMatches(have [][]byte, m MoveRegistration) bool {
	return len(m.Operation) > 0 && len(m.Entries) > len(have) &&
		SameChain(have, m.Expected) && SameChain(have, m.Entries[:len(have)])
}

// SameChain compares complete canonical chains, including an absent chain.
func SameChain(a, b [][]byte) bool { return slices.EqualFunc(a, b, bytes.Equal) }

// Sessions stores auth nonces and bearer tokens (spec/api/client-stage1.md).
type Sessions interface {
	PutNonce(ctx context.Context, id string, device, nonce []byte, expires int64) error
	// TakeNonce consumes a nonce. ErrNotFound if it's unknown, used, or expired.
	TakeNonce(ctx context.Context, id string, device, nonce []byte, now int64) error
	// UseNonce records a server-to-server request nonce until `expires`, in one step, and
	// reports whether it was fresh: false if the same key is recorded and not yet expired
	// (SPEC §8.3). Keys start with "s2s|", so they never meet the auth nonces above.
	UseNonce(ctx context.Context, key string, expires, now int64) (fresh bool, err error)
	// PruneNonces deletes every nonce, of either kind, that expired before `now`.
	PruneNonces(ctx context.Context, now int64) (int, error)
	CreateToken(ctx context.Context, tokenHash []byte, id string, device []byte, name string, expires int64) error
	// LookupToken also extends the token's expiry.
	LookupToken(ctx context.Context, tokenHash []byte, now int64) (id string, device []byte, err error)
	RevokeToken(ctx context.Context, tokenHash []byte) error
	RevokeDevice(ctx context.Context, id string, device []byte) error
}

// KeyPackage is one stored MLS key package. The server never parses it (SPEC §2.3).
type KeyPackage struct {
	Device     []byte
	Data       []byte
	LastResort bool
}

// KeyPackages stores MLS key packages per device (SPEC §11.4).
type KeyPackages interface {
	Upload(ctx context.Context, id string, device []byte, packages [][]byte, lastResort []byte) (count int, err error)
	// Clear deletes a device's unclaimed one-time key packages (before a replacing upload).
	Clear(ctx context.Context, id string, device []byte) error
	Count(ctx context.Context, id string, device []byte) (count int, hasLastResort bool, err error)
	// Claim removes and returns one package per listed device, falling back to last-resort ones.
	Claim(ctx context.Context, id string, devices [][]byte) ([]KeyPackage, error)
}

// Contact states (spec/api/client-stage1.md).
const (
	StateContact    = "contact"
	StatePendingIn  = "pending-in"
	StatePendingOut = "pending-out"
	StateBlocked    = "blocked"
	// StateDeclined marks someone the owner declined: their requests are dropped for
	// 30 days (SPEC §9.3). It's never listed, and never gets chain pushes.
	StateDeclined = "declined"
)

type Contact struct {
	ID      string
	State   string
	Since   int64
	Request []byte // encoded signed contact-request, for pending-in
}

// Contacts stores each local user's contact list, used as an allowlist (SPEC §9, §10.3).
type Contacts interface {
	Get(ctx context.Context, owner, other string) (*Contact, error)
	Put(ctx context.Context, owner string, c Contact) error
	Delete(ctx context.Context, owner, other string) error
	List(ctx context.Context, owner string, after string, limit int) ([]Contact, string, error)
	// Groups allowlist.
	AllowGroup(ctx context.Context, owner string, group []byte) error
	DisallowGroup(ctx context.Context, owner string, group []byte) error
	GroupAllowed(ctx context.Context, owner string, group []byte) (bool, error)
	// Owners lists the local users who have `other` in their contacts (any state but blocked or declined).
	Owners(ctx context.Context, other string) ([]string, error)
}

// Invite is a contact invite code (SPEC §9.1). Only its SHA-256 is stored.
type Invite struct {
	Hash    []byte // SHA-256 of the code
	Owner   string
	Public  bool  // published on the owner's profile: held to rate limits (SPEC §9.5)
	Uses    int   // uses left; -1 means unlimited
	Expires int64 // 0 means never
	Created int64
}

// Invites stores each local user's contact invite codes (SPEC §9.1).
type Invites interface {
	Create(ctx context.Context, inv Invite) error
	// Revoke deletes a code. ErrNotFound if the owner has no such code.
	Revoke(ctx context.Context, owner string, hash []byte) error
	List(ctx context.Context, owner string, now int64) ([]Invite, error)
	// Use spends one use of a code and returns it. ErrNotFound if it's unknown,
	// used up, or expired.
	Use(ctx context.Context, owner string, hash []byte, now int64) (*Invite, error)
}

// Item is one stored inbox item: either a delivery or a server notice.
type Item struct {
	Cursor   string
	TS       int64
	Delivery []byte // encoded delivery, or nil
	Notice   []byte // encoded notice, or nil
}

// Inbox stores per-user inboxes and per-device ack positions (SPEC §9.4).
type Inbox interface {
	Append(ctx context.Context, owner string, it Item) (cursor string, err error)
	List(ctx context.Context, owner string, device []byte, after string, limit int) (items []Item, next string, gap bool, err error)
	Ack(ctx context.Context, owner string, device []byte, upto string) error
	// Prune deletes items every listed device has acked, and items older than `before` (SPEC §9.4).
	Prune(ctx context.Context, owner string, devices [][]byte, before int64) error
	// Deliver stores a delivery in an owner's inbox unless its ID was delivered to that owner
	// before (SPEC §9.5), recording the ID and appending the item in one transaction, so a
	// failure leaves neither. isNew is false, with no cursor, for a repeat.
	Deliver(ctx context.Context, owner string, id []byte, it Item) (cursor string, isNew bool, err error)
	// PruneSeen forgets delivery IDs recorded before `before`. A repeat after that is stored
	// again, so `before` has to be older than any retry: the outbox gives up after 72 hours.
	PruneSeen(ctx context.Context, before int64) (int, error)
}

// Sent keeps the result of each delivery a local user sent, by sender and delivery ID, so
// a resubmitted ID gets the original result instead of being delivered again
// (spec/api/client-stage1.md, POST send).
type Sent interface {
	// Get returns the stored result, or ErrNotFound.
	Get(ctx context.Context, sender string, id []byte) ([]byte, error)
	// Put stores a result. A result already stored for the same ID is kept.
	Put(ctx context.Context, sender string, id, result []byte, ts int64) error
	// Prune deletes results stored before `before`.
	Prune(ctx context.Context, before int64) (int, error)
}

// HubGroup is the hub's state for one group (SPEC §11.6).
type HubGroup struct {
	Group    []byte
	Epoch    uint64
	EpochKey []byte // public half of the current epoch key; while Awaiting, the one-time `reg` key
	// Awaiting: the last commit used the `reg` fallback, and this epoch's key isn't
	// registered yet (SPEC §11.6). No commits until it is.
	Awaiting bool
}

// Commit is one accepted commit kept by the hub for 30 days.
type Commit struct {
	Epoch   uint64
	Data    []byte
	Receipt wire.Signed
	TS      int64 // when the hub accepted it
	// Request is the signed commit-request that was accepted, as received, so an exact
	// retry gets the same receipt back (SPEC §11.6). Empty for commits stored before
	// schema version 4.
	Request []byte
}

// Hub sequences commits for groups this server hosts. Writes MUST be durable
// before a receipt goes out (SPEC §11.6).
type Hub interface {
	Register(ctx context.Context, g HubGroup) error // ErrConflict if the group exists
	Group(ctx context.Context, group []byte) (*HubGroup, error)
	// Accept atomically advances epoch N to N+1 if the group is still at N and not
	// awaiting a key, replaces the epoch key (or, with awaiting, stores the `reg` key),
	// and stores the commit. ErrConflict if not.
	Accept(ctx context.Context, group []byte, epoch uint64, nextKey []byte, awaiting bool, c Commit) error
	// SetKey registers epoch `epoch`'s key after a `reg` commit: only if the group is at
	// that epoch, awaiting, and its stored `reg` key is `reg`. ErrConflict if not.
	SetKey(ctx context.Context, group []byte, epoch uint64, reg, next []byte) error
	// Commits returns kept commits with epoch >= from, in order.
	Commits(ctx context.Context, group []byte, from uint64) ([]Commit, error)
	// PruneCommits deletes commits accepted before `before` (30 days, SPEC §11.6).
	PruneCommits(ctx context.Context, before int64) error
}

// Remote caches the chains of identities that live on other servers (SPEC §6.5).
type Remote interface {
	// Put replaces the cached chain for id. home is the server the chain names.
	Put(ctx context.Context, id, home string, entries [][]byte) error
	Get(ctx context.Context, id string) (home string, entries [][]byte, err error)
	// HasContactOn reports whether any local user has, as a full contact, an identity
	// whose cached chain names `home` as its homeserver.
	HasContactOn(ctx context.Context, home string) (bool, error)
}

// OutboxItem is one S2S request waiting to be sent (SPEC §9.5).
type OutboxItem struct {
	ID       int64
	Dest     string // destination server name
	Path     string // S2S path, e.g. "deliver"
	Body     []byte // JSON body of the s2s-request, unsigned
	Attempts int
	Created  int64
}

// Outbox holds S2S requests until they're delivered or expire (72 hours, SPEC §9.5).
type Outbox interface {
	Enqueue(ctx context.Context, dest, path string, body []byte, now int64) error
	Due(ctx context.Context, now int64, limit int) ([]OutboxItem, error)
	Done(ctx context.Context, id int64) error
	Retry(ctx context.Context, id int64, next int64) error
}

// Profiles stores each local identity's signed public profile (SPEC §13.1).
type Profiles interface {
	// Put stores a profile if v is higher than the stored one's. ErrConflict if not.
	Put(ctx context.Context, id string, v int64, signed []byte) error
	Get(ctx context.Context, id string) ([]byte, error)
}

// MediaMeta describes one stored file (SPEC §14) or profile picture (SPEC §13.1).
type MediaMeta struct {
	ID      []byte
	Owner   string
	Size    int64
	SHA256  []byte
	Mime    string // the image type for public media; "" for encrypted files
	Public  bool
	Created int64
	Removed bool // deleted after a report: fetches answer 410 removed
	Expired bool // past 30 days: fetches answer 410 expired
}

// Media stores files. Bytes and metadata are written together.
type Media interface {
	// Write stores up to max bytes from r under m.ID, filling in m.Size and m.SHA256.
	// It returns ErrOverQuota if r holds more than max.
	Write(ctx context.Context, m *MediaMeta, r io.Reader, max int64) error
	Get(ctx context.Context, id []byte) (*MediaMeta, error)
	Open(ctx context.Context, id []byte) (io.ReadCloser, error)
	// Usage is the bytes an owner has stored, not counting removed files.
	Usage(ctx context.Context, owner string) (int64, error)
	// Remove deletes a file's bytes but keeps its record, so fetches answer 410 removed.
	Remove(ctx context.Context, id []byte) error
	// Expire deletes the bytes of non-public files created before `before`, and marks
	// their records expired, so fetches can say so.
	Expire(ctx context.Context, before int64) (int, error)
}

// Account stores the wrapped account keys and the account data blob (SPEC §7.4).
type Account interface {
	// Keys returns the stored wrapped-key objects, as JSON.
	Keys(ctx context.Context, id string) ([][]byte, error)
	// Key returns the wrapped key stored under a slot name, or ErrNotFound.
	Key(ctx context.Context, id, via string) ([]byte, error)
	SetKey(ctx context.Context, id, via string, wrapped []byte) error
	RemoveKey(ctx context.Context, id, via string) error
	// UpdateKeys reads the identity's local chain and every key slot, calls decide, and
	// applies the changes it returns, all or nothing. It is serialized with every chain
	// write (Create, Append, Fork, RegisterMove), so what decide saw is still true when its
	// changes land: recovery-wrap promotion and cleanup depend on that (SPEC §6.3).
	// decide must not block or call the store. Its error is returned unchanged, with
	// nothing written. ErrNotFound if the identity has no local chain.
	UpdateKeys(ctx context.Context, id string, decide func(chain [][]byte, slots []KeySlot) ([]KeyChange, error)) error
	// Data returns the current version (0 if never written) and ciphertext.
	Data(ctx context.Context, id string) (version int64, ct []byte, err error)
	// PutData writes if replaces is the current version. ErrConflict if not.
	PutData(ctx context.Context, id string, replaces int64, ct []byte) (version int64, err error)
}

// KeySlot is one stored wrapped key, with when it was stored (Unix seconds, server clock).
type KeySlot struct {
	Slot    string
	Wrapped []byte
	Stored  int64
}

// KeyChange writes Wrapped to Slot, stamped Stored, or with Delete removes the slot. A
// change with neither is invalid, and fails the whole update.
type KeyChange struct {
	Slot    string
	Wrapped []byte
	Stored  int64
	Delete  bool
}

// ErrInvalidChange is a KeyChange that neither writes nor deletes.
var ErrInvalidChange = errors.New("store: invalid key change")

// Segment is one backup segment (SPEC §7.5).
type Segment struct {
	Seq      int64
	CT       []byte
	Snapshot bool
	Size     int64 // len(CT), filled in by List
}

// Backups stores each identity's backup segments (SPEC §7.5).
type Backups interface {
	// Put stores a segment. The same seq with the same bytes is a no-op; with other bytes
	// it's ErrExists; a seq at or below the newest stored one is ErrConflict. A snapshot
	// deletes every lower seq.
	Put(ctx context.Context, id string, s Segment) error
	List(ctx context.Context, id string) ([]Segment, error) // Seq order, with Size and no CT
	Get(ctx context.Context, id string, seq int64) (*Segment, error)
	Usage(ctx context.Context, id string) (int64, error)
}

// Report is a report kept for this server's admins (SPEC §16.3).
type Report struct {
	Received int64
	Origin   string // the server it came from; this server's own name for local users
	Reporter string
	Reported string
	Body     []byte // the report object, as JSON
}

// Reports keeps reports for admins.
type Reports interface {
	Add(ctx context.Context, r Report) error
	List(ctx context.Context, limit int) ([]Report, error)
}
