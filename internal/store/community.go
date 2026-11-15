package store

import (
	"context"
	"io"
)

// Community servers (SPEC §16). One rerouted process can serve several server names as
// community servers, each hosting exactly one community (SPEC §16.1). Everything here is
// keyed by that server name, so two communities on one process never see each other's
// rows. Wire version 2 only: there's no version 1 view of any of it.

// Community is a community this server hosts under one of its names.
type Community struct {
	Name    string // the server name it's hosted under
	ID      []byte // its identifier: the hash of its create entry (SPEC §16.2.1)
	Group   []byte // its members group, nil until registered (after a move-in, SPEC §16.6)
	Created int64
	// Listed, for a move-in: the identities the owner's signed member list names, the only
	// ones who may join by registering for the members group (SPEC §16.6). Create only.
	Listed []string
}

// CommunityMember is one identity the community server counts as a member, for
// authorization (spec/api/community.md, "Membership as the server sees it").
type CommunityMember struct {
	ID    string
	Home  string // its homeserver when it joined, for domain bans
	Since int64
}

// CGroup is the hub's state for one of a community's groups (SPEC §11.6, §16.5).
type CGroup struct {
	Name     string
	Group    []byte
	See      string // "" for the members group; else the see list it carries (cchain.SeeKey)
	Epoch    uint64
	Key      []byte // the current epoch key's public half, or the `reg` key while Awaiting
	Awaiting bool
	Info     []byte // GroupInfo for the current epoch
	Tree     []byte // the hash of the current epoch's ratchet tree
	TreeSize int64
}

// CCommit is one accepted commit, kept 30 days (SPEC §11.6).
type CCommit struct {
	Epoch   uint64
	Data    []byte
	Receipt []byte // the encoded commit-receipt
	Request []byte // the accepted commit-request, as received, for exact retries
	Proof   []byte // a code join's join-proof, or nil
	TS      int64
}

// CAccept is the hub step's outcome for one commit, applied in one transaction: the
// group moves from Epoch to Epoch+1 with Key (or awaits one), the commit is kept, and
// Info and Tree become the new epoch's.
type CAccept struct {
	Group    []byte
	Epoch    uint64
	Key      []byte
	Awaiting bool
	Commit   CCommit
	Info     []byte // nil keeps none
	Tree     []byte
	TreeSize int64
	// Join, for a code join: the same transaction counts the code's use (ErrOverQuota if
	// it has none left, or if the community would pass Cap members), makes the identity a
	// member, and registers its device for the group.
	Join *CJoin
}

// CJoin is a code join's membership change (SPEC §16.6).
type CJoin struct {
	ID, Home string
	Dev      []byte
	Code     []byte // the hash of the code's key
	Limit    int    // the code's use limit; 0 for none
	Cap      int    // the member cap
}

// CItem is one inbox item in a community: a delivery to a group's registered devices, a
// Welcome or notice to one device or identity, or a notice to every member.
type CItem struct {
	Cursor int64
	TS     int64
	// Group traffic goes to every device registered for Group, except FromID's FromDev.
	Group   []byte
	FromID  string
	FromDev []byte
	// Or to one identity's devices (ToDev nil), or one device.
	ToID  string
	ToDev []byte
	// Or to every member.
	Members bool
	// Channel and Seq for a text channel's message (SPEC §16.5); Deleted is the seq of
	// the delete that dropped it, with Delivery cleared.
	Channel, Seq, Deleted uint64
	// Numbered: Put gives it the next number in Channel's sequence, in Seq.
	Numbered         bool
	Delivery, Notice []byte
}

// CReg is one device registered for a group's traffic.
type CReg struct {
	ID  string
	Dev []byte
}

// CRequest is a pending request to join (POST join/request).
type CRequest struct {
	ID, Home   string
	TS         int64
	Approver   string // the moderator holding it, while Approved is within 10 minutes
	ApprovedAt int64
}

// CSegment is one history segment (SPEC §16.5).
type CSegment struct {
	Channel    uint64
	Start, End uint64
	CT         []byte // nil in List
	Size       int64
	TS         int64
}

// CMedia is one file uploaded to a community (SPEC §16.4).
type CMedia struct {
	ID      []byte
	Author  string
	Size    int64
	SHA256  []byte
	Created int64
	Removed bool // deleted with its message
	Expired bool // past the community's retention
}

// CReport is a report to a community's moderators (SPEC §16.7).
type CReport struct {
	N        int64 // its place in the list, for pagination
	ID       []byte
	TS       int64
	Reporter string
	Body     []byte // the report object
	At       []byte // the "at" list as JSON, or nil
}

// CKeyPackage is a key package in a community's pool (spec/api/community.md).
type CKeyPackage struct {
	Device     []byte
	Data       []byte
	Binding    []byte
	LastResort bool
}

// Communities stores the communities this server hosts.
type Communities interface {
	// Create stores a new community under name: its first chain entries and, with
	// c.Group, its members group (g), and makes owner its first member. ErrExists if
	// the name already hosts a community.
	Create(ctx context.Context, c Community, entries, hashes [][]byte, owner CommunityMember, g *CGroup) error
	Get(ctx context.Context, name string) (*Community, error)
	// Entries returns the chain's entries with seq > after, in order.
	Entries(ctx context.Context, name string, after int64) ([][]byte, error)
	// Append adds the entry at seq if the head is seq-1 (ErrConflict otherwise), and in
	// the same transaction removes the members in remove (a ban's kick).
	Append(ctx context.Context, name string, seq uint64, entry, hash []byte, remove []string) error

	// Members.
	AddMember(ctx context.Context, name string, m CommunityMember) error
	// RemoveMember ends a membership and every registration of its devices.
	RemoveMember(ctx context.Context, name, id string) error
	Member(ctx context.Context, name, id string) (*CommunityMember, error) // ErrNotFound
	Members(ctx context.Context, name string) ([]CommunityMember, error)
	MemberCount(ctx context.Context, name string) (int, error)
	// Listed reports whether a move-in's member list names id.
	Listed(ctx context.Context, name, id string) (bool, error)

	// Sessions.
	CreateToken(ctx context.Context, name string, hash []byte, id, home string, dev []byte, expires int64) error
	// LookupToken also extends the token's expiry.
	LookupToken(ctx context.Context, name string, hash []byte, now int64) (id, home string, dev []byte, err error)
	RevokeToken(ctx context.Context, hash []byte) error
	RevokeDevice(ctx context.Context, name, id string, dev []byte) error
	// SessionIDs lists the identities with an unexpired session.
	SessionIDs(ctx context.Context, name string, now int64) ([]string, error)
	// SessionDevices lists an identity's devices with an unexpired session.
	SessionDevices(ctx context.Context, name, id string, now int64) ([][]byte, error)

	// Key packages.
	UploadKPs(ctx context.Context, name, id string, dev []byte, kps []CKeyPackage, lastResort *CKeyPackage, replace bool) (int, error)
	CountKPs(ctx context.Context, name, id string, dev []byte) (int, bool, error)
	ClaimKPs(ctx context.Context, name, id string, devs [][]byte) ([]CKeyPackage, error)
	// PruneKPs deletes the packages of identities that aren't members and have had no
	// session since `before`.
	PruneKPs(ctx context.Context, name string, before int64) (int, error)

	// Groups, with the community server as their hub (SPEC §11.6, §16.5).
	// RegisterGroup: ErrConflict if the group ID is known here, in any community or as a
	// homeserver hub's group. A members group (See "") also becomes the community's Group.
	RegisterGroup(ctx context.Context, g CGroup) error
	Group(ctx context.Context, group []byte) (*CGroup, error)
	Groups(ctx context.Context, name string) ([]CGroup, error)
	// Accept applies a hub step. ErrConflict if the group isn't at a.Epoch or awaits a key.
	Accept(ctx context.Context, a CAccept) error
	SetKey(ctx context.Context, group []byte, epoch uint64, reg, next []byte) error
	Commits(ctx context.Context, group []byte, from uint64) ([]CCommit, error)
	// Register lets a device receive a group's traffic from now on.
	Register(ctx context.Context, name string, group []byte, id string, dev []byte) error
	Unregister(ctx context.Context, group []byte, id string, dev []byte) error
	// UnregisterIdentity stops delivering group to an identity's devices.
	UnregisterIdentity(ctx context.Context, group []byte, id string) error
	Registered(ctx context.Context, group []byte, id string, dev []byte) (bool, error)
	// Regs lists the devices registered for group.
	Regs(ctx context.Context, group []byte) ([]CReg, error)

	// Ratchet trees: bytes in files, records in the database.
	PutTree(ctx context.Context, name string, r io.Reader, max int64, uploader string, now int64) (hash []byte, size int64, err error)
	TreeSize(ctx context.Context, name string, hash []byte) (int64, error) // ErrNotFound
	// UseTree records that group's epoch uses the tree, and keeps it until keep.
	UseTree(ctx context.Context, name string, hash, group []byte, epoch uint64, keep int64) error
	// TreeFor opens the tree group used at epoch: ErrNotFound if there's none.
	TreeFor(ctx context.Context, group []byte, epoch uint64) (io.ReadCloser, int64, error)
	// PruneTrees deletes trees no accepted commit named, uploaded before unusedBefore,
	// and used ones whose keep has passed.
	PruneTrees(ctx context.Context, unusedBefore, now int64) (int, error)

	// The inbox.
	// Put stores items in one transaction, giving each channel message the next number in
	// its channel (Seq is filled in), and returns them with their cursors.
	Put(ctx context.Context, name string, items []CItem) ([]CItem, error)
	List(ctx context.Context, name, id string, dev []byte, after int64, limit int) ([]CItem, error)
	// Pruned is the newest cursor dropped from the community's inbox by age.
	Pruned(ctx context.Context, name string) (int64, error)
	Ack(ctx context.Context, name, id string, dev []byte, upto int64) error
	ChannelItems(ctx context.Context, name string, channel, from uint64, limit int) ([]CItem, error)
	ChannelItem(ctx context.Context, name string, channel, seq uint64) (*CItem, error)
	ChannelHead(ctx context.Context, name string, channel uint64) (uint64, error)
	// DeleteItem drops a channel message's ciphertext, keeping its number, and records
	// when, for history segments (SPEC §16.7).
	DeleteItem(ctx context.Context, name string, channel, seq, by uint64, now int64) error
	// Prune drops items, commits, and sent results older than before.
	Prune(ctx context.Context, before int64) error
	SentResult(ctx context.Context, name, sender string, id []byte) ([]byte, error)
	PutSentResult(ctx context.Context, name, sender string, id, result []byte, now int64) error

	// Codes: uses counted by the server (SPEC §16.6).
	CodeUses(ctx context.Context, name string, code []byte) (int, error)

	// Join requests.
	PutRequest(ctx context.Context, name string, r CRequest) error // no change if one is pending
	Request(ctx context.Context, name, id string) (*CRequest, error)
	Requests(ctx context.Context, name string, after string, limit int) ([]CRequest, error) // by identifier
	CountRequests(ctx context.Context, name string) (int, error)
	// HoldRequest marks a request approved by approver at now, unless another approver
	// holds it since after `since` (ErrConflict).
	HoldRequest(ctx context.Context, name, id, approver string, now, since int64) error
	DeleteRequest(ctx context.Context, name, id string) error

	// History segments.
	PutSegment(ctx context.Context, name string, s CSegment, replace bool) error // ErrConflict, ErrExists
	Segments(ctx context.Context, name string, channel uint64, after uint64, limit int) ([]CSegment, error)
	Segment(ctx context.Context, name string, channel, start uint64) (*CSegment, error)
	DeleteSegments(ctx context.Context, name string, channel uint64) error
	SegmentUsage(ctx context.Context, name string) (int64, error)
	// DeletedSince reports whether a message numbered in [start, end] was deleted after ts.
	DeletedSince(ctx context.Context, name string, channel, start, end uint64, ts int64) (bool, error)

	// Files.
	PutMedia(ctx context.Context, name string, m *CMedia, r io.Reader, max int64) error
	Media(ctx context.Context, name string, id []byte) (*CMedia, error)
	OpenMedia(ctx context.Context, name string, id []byte) (io.ReadCloser, error)
	MediaUsage(ctx context.Context, name string) (int64, error)
	RemoveMedia(ctx context.Context, name string, id []byte) error
	ExpireMedia(ctx context.Context, name string, before int64) (int, error)

	// Reports.
	AddReport(ctx context.Context, name string, r CReport) error
	Reports(ctx context.Context, name string, after int64, limit int) ([]CReport, error)
	CloseReport(ctx context.Context, name string, id []byte) error
}
