package cchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Decoding community entries and their ops (SPEC §16.2.1, §16.2.3). Everything is closed
// (§20.2): a member an object doesn't define is 400 bad-request. An op, permission, or
// channel kind this version doesn't know is 400 unknown-kind.

const (
	maxSealedCT = 508 // bytes (§16.2.4)
	maxRank     = 1000
	maxSlow     = 21600
)

// sealed is a value encrypted under a metadata key (§16.2.4). The server never opens one.
type sealedField struct {
	present, null bool
}

// pop is one decoded op, with what's present.
type pop struct {
	Op string

	ID    uint64
	hasID bool

	Rank    int
	hasRank bool

	Perms    Perms
	hasPerms bool
	dupPerms bool

	Name, Desc     string // create and set-name: readable
	hasDesc        bool
	name, color    sealedField
	topic          sealedField
	See, Write     []uint64
	hasSee, hasWrt bool
	Kind           string
	History        bool
	hasHistory     bool
	Slow           int
	hasSlow        bool
	Max, Cast      uint64
	hasMax         bool
	hasCast        bool

	Member, Domain, To, Server string

	Roles []uint64
	IDs   []uint64

	Key     []byte
	Exp     int64
	hasExp  bool
	Uses    uint64
	hasUses bool
	Public  bool // add-code: "public": true; create and set-settings: the setting
	Code    []byte

	Approval bool
	Everyone Perms

	Until int64

	members int // members besides "op" and "id"
}

// entryBody is a community-entry's decoded body.
type entryBody struct {
	Community    []byte
	hasCommunity bool
	Seq          uint64
	Prev         []byte
	hasPrev      bool
	TS           int64
	By           string
	Ops          []pop
}

func badRequest(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: wire.ErrCodeBadRequest, Msg: msg}
}

func unknownKind(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: wire.ErrCodeUnknownKind, Msg: msg}
}

// fields reads an object's members, remembering which it read, so the rest can be refused.
type fields struct {
	m    map[string]json.RawMessage
	used map[string]bool
	err  *Error
	what string
}

func newFields(raw json.RawMessage, what string) (*fields, *Error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, badRequest(what + " must be an object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, badRequest(what + ": " + err.Error())
	}
	return &fields{m: m, used: map[string]bool{}, what: what}, nil
}

func (f *fields) fail(e *Error) {
	if f.err == nil {
		f.err = e
	}
}

func (f *fields) get(k string, required bool) (json.RawMessage, bool) {
	v, ok := f.m[k]
	if !ok {
		if required {
			f.fail(badRequest(f.what + ": missing " + k))
		}
		return nil, false
	}
	f.used[k] = true
	return bytes.TrimSpace(v), true
}

func isNull(v json.RawMessage) bool { return string(v) == "null" }

func (f *fields) uint(k string, required bool) (uint64, bool) {
	v, ok := f.get(k, required)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(string(v), 10, 64)
	if err != nil || n > 1<<53-1 {
		f.fail(badRequest(f.what + ": " + k + " must be an unsigned integer"))
		return 0, false
	}
	return n, true
}

func (f *fields) str(k string, required bool) (string, bool) {
	v, ok := f.get(k, required)
	if !ok {
		return "", false
	}
	if len(v) == 0 || v[0] != '"' {
		f.fail(badRequest(f.what + ": " + k + " must be a string"))
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		f.fail(badRequest(f.what + ": " + k + ": " + err.Error()))
		return "", false
	}
	return s, true
}

func (f *fields) boolean(k string, required bool) (bool, bool) {
	v, ok := f.get(k, required)
	if !ok {
		return false, false
	}
	switch string(v) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	f.fail(badRequest(f.what + ": " + k + " must be true or false"))
	return false, false
}

// bytesN reads a base64url byte string of exactly n bytes, or any length if n is 0.
func (f *fields) bytesN(k string, n int, required bool) ([]byte, bool) {
	s, ok := f.str(k, required)
	if !ok {
		return nil, false
	}
	b, err := wire.DecodeB64(s)
	if err != nil || (n > 0 && len(b) != n) {
		f.fail(badRequest(f.what + ": " + k + " has the wrong form"))
		return nil, false
	}
	return b, true
}

func (f *fields) identifier(k string, required bool) (string, bool) {
	s, ok := f.str(k, required)
	if ok && !wire.ValidIdentityID(s) {
		f.fail(badRequest(f.what + ": " + k + " isn't an identifier"))
		return "", false
	}
	return s, ok
}

func (f *fields) serverName(k string, required bool) (string, bool) {
	s, ok := f.str(k, required)
	if ok && !validServerName(s) {
		f.fail(badRequest(f.what + ": " + k + " isn't a server name"))
		return "", false
	}
	return s, ok
}

func (f *fields) uints(k string, required, nonEmpty bool) ([]uint64, bool) {
	v, ok := f.get(k, required)
	if !ok {
		return nil, false
	}
	var raw []json.RawMessage
	if len(v) == 0 || v[0] != '[' || json.Unmarshal(v, &raw) != nil {
		f.fail(badRequest(f.what + ": " + k + " must be an array"))
		return nil, false
	}
	if nonEmpty && len(raw) == 0 {
		f.fail(badRequest(f.what + ": " + k + " can't be empty"))
		return nil, false
	}
	out := make([]uint64, 0, len(raw))
	for _, e := range raw {
		n, err := strconv.ParseUint(string(bytes.TrimSpace(e)), 10, 64)
		if err != nil || n > 1<<53-1 {
			f.fail(badRequest(f.what + ": " + k + " must hold unsigned integers"))
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// perms reads a list of permissions. An unknown one is unknown-kind; a repeated one is
// recorded, for the op rules to refuse.
func (f *fields) perms(k string, required bool) (p Perms, dup, present bool) {
	v, ok := f.get(k, required)
	if !ok {
		return 0, false, false
	}
	var raw []json.RawMessage
	if len(v) == 0 || v[0] != '[' || json.Unmarshal(v, &raw) != nil {
		f.fail(badRequest(f.what + ": " + k + " must be an array"))
		return 0, false, false
	}
	for _, e := range raw {
		e = bytes.TrimSpace(e)
		var s string
		if len(e) == 0 || e[0] != '"' || json.Unmarshal(e, &s) != nil {
			f.fail(badRequest(f.what + ": " + k + " must hold strings"))
			return 0, false, false
		}
		bit, known := permNames[s]
		if !known {
			f.fail(unknownKind("unknown permission " + strconv.Quote(s)))
			return 0, false, false
		}
		if p&bit != 0 {
			dup = true
		}
		p |= bit
	}
	return p, dup, true
}

// sealed reads a sealed value (§16.2.4): closed, a 32-byte key hash and a ct of at most
// 508 bytes. With nullable, JSON null is allowed and means "remove".
func (f *fields) sealed(k string, required, nullable bool) sealedField {
	v, ok := f.get(k, required)
	if !ok {
		return sealedField{}
	}
	if nullable && isNull(v) {
		return sealedField{present: true, null: true}
	}
	sf, err := newFields(v, f.what+"."+k)
	if err != nil {
		f.fail(err)
		return sealedField{}
	}
	sf.bytesN("key", 32, true)
	ct, ok := sf.bytesN("ct", 0, true)
	if ok && len(ct) > maxSealedCT {
		sf.fail(badRequest(f.what + "." + k + ": ct is over 508 bytes"))
	}
	sf.closed()
	if sf.err != nil {
		f.fail(sf.err)
		return sealedField{}
	}
	return sealedField{present: true}
}

// closed refuses members nobody read.
func (f *fields) closed() {
	for k := range f.m {
		if !f.used[k] {
			f.fail(badRequest(f.what + ": unexpected member " + strconv.Quote(k)))
			return
		}
	}
}

var permNames = map[string]Perms{"talk": Talk, "invite": Invite, "moderate": Moderate, "administrate": Administrate}

// decodeOp decodes one op by its "op" member.
func decodeOp(raw json.RawMessage, i int) (pop, *Error) {
	f, e := newFields(raw, "op "+strconv.Itoa(i))
	if e != nil {
		return pop{}, e
	}
	var o pop
	name, ok := f.str("op", true)
	if !ok {
		return pop{}, f.err
	}
	o.Op = name
	before := len(f.used)
	switch name {
	case "create":
		o.Server, _ = f.serverName("server", true)
		o.Name, _ = f.str("name", true)
		o.Desc, o.hasDesc = f.str("desc", false)
		o.Public, _ = f.boolean("public", true)
		o.Approval, _ = f.boolean("approval", true)
		o.Everyone, o.dupPerms, _ = f.perms("everyone", true)
	case "set-name":
		o.Name, _ = f.str("name", true)
		o.Desc, o.hasDesc = f.str("desc", false)
	case "set-settings":
		o.Public, _ = f.boolean("public", true)
		o.Approval, _ = f.boolean("approval", true)
	case "add-role", "edit-role":
		edit := name == "edit-role"
		o.ID, o.hasID = f.uint("id", true)
		if r, ok := f.uint("rank", !edit); ok {
			if r < 1 || r > maxRank {
				f.fail(badRequest("rank must be from 1 to 1000"))
			}
			o.Rank, o.hasRank = int(r), true
		}
		o.Perms, o.dupPerms, o.hasPerms = f.perms("perms", !edit)
		o.name = f.sealed("name", !edit, false)
		o.color = f.sealed("color", false, edit)
	case "remove-role":
		o.ID, o.hasID = f.uint("id", true)
	case "assign-roles":
		o.Member, _ = f.identifier("member", true)
		o.Roles, _ = f.uints("roles", true, false)
	case "add-channel", "edit-channel":
		edit := name == "edit-channel"
		o.ID, o.hasID = f.uint("id", true)
		o.name = f.sealed("name", !edit, false)
		o.topic = f.sealed("topic", false, edit)
		o.See, o.hasSee = f.uints("see", !edit, true)
		o.Write, o.hasWrt = f.uints("write", !edit, true)
		if !edit {
			o.Kind, _ = f.str("kind", true)
			switch o.Kind {
			case "text", "voice":
			default:
				if f.err == nil {
					f.fail(unknownKind("unknown channel kind " + strconv.Quote(o.Kind)))
				}
			}
		}
		if !edit && o.Kind == "voice" {
			o.Max, o.hasMax = f.uint("max", true)
			o.Cast, o.hasCast = f.uint("cast", true)
		} else if !edit && o.Kind == "text" {
			o.History, o.hasHistory = f.boolean("history", true)
			o.slow(f, true)
		} else if edit {
			o.History, o.hasHistory = f.boolean("history", false)
			o.slow(f, false)
			o.Max, o.hasMax = f.uint("max", false)
			o.Cast, o.hasCast = f.uint("cast", false)
		}
	case "remove-channel":
		o.ID, o.hasID = f.uint("id", true)
	case "order-channels":
		o.IDs, _ = f.uints("ids", true, true)
	case "add-code":
		o.Key, _ = f.bytesN("key", wire.CompositePublicKeySize, true)
		if o.Key != nil {
			if _, err := wire.ParseCompositePublicKey(o.Key); err != nil {
				f.fail(badRequest("key isn't a composite public key"))
			}
		}
		if exp, ok := f.uint("exp", false); ok {
			o.Exp, o.hasExp = int64(exp), true
		}
		o.Uses, o.hasUses = f.uint("uses", false)
		if pub, ok := f.boolean("public", false); ok {
			if !pub {
				f.fail(badRequest(`"public" is only ever true`))
			}
			o.Public = true
		}
	case "revoke-code":
		o.Code, _ = f.bytesN("code", 32, true)
	case "ban", "unban":
		m, hasM := f.identifier("member", false)
		d, hasD := f.serverName("domain", false)
		if f.err == nil && hasM == hasD {
			f.fail(badRequest(name + " takes exactly one of member and domain"))
		}
		o.Member, o.Domain = m, d
	case "timeout":
		o.Member, _ = f.identifier("member", true)
		if u, ok := f.uint("until", true); ok {
			o.Until = int64(u)
		}
	case "transfer-ownership":
		o.To, _ = f.identifier("to", true)
	case "set-home":
		o.Server, _ = f.serverName("server", true)
	default:
		return pop{}, unknownKind("unknown op " + strconv.Quote(name))
	}
	o.members = len(f.used) - before
	if o.hasID {
		o.members--
	}
	f.closed()
	if f.err != nil {
		return pop{}, f.err
	}
	return o, nil
}

func (o *pop) slow(f *fields, required bool) {
	if s, ok := f.uint("slow", required); ok {
		if s > maxSlow {
			f.fail(badRequest("slow must be from 0 to 21600"))
		}
		o.Slow, o.hasSlow = int(s), true
	}
}

// decodeBody decodes a community-entry body, and each op.
func decodeBody(b string) (*entryBody, *Error) {
	if err := wire.CheckIJSON([]byte(b)); err != nil {
		return nil, badRequest("body: " + err.Error())
	}
	f, e := newFields(json.RawMessage(b), "community-entry")
	if e != nil {
		return nil, e
	}
	var eb entryBody
	eb.Community, eb.hasCommunity = f.bytesN("community", 32, false)
	eb.Seq, _ = f.uint("seq", true)
	eb.Prev, eb.hasPrev = f.bytesN("prev", 32, false)
	if ts, ok := f.uint("ts", true); ok {
		eb.TS = int64(ts)
	}
	eb.By, _ = f.identifier("by", true)
	opsRaw, ok := f.get("ops", true)
	f.closed()
	if f.err != nil {
		return nil, f.err
	}
	var ops []json.RawMessage
	if !ok || len(opsRaw) == 0 || opsRaw[0] != '[' || json.Unmarshal(opsRaw, &ops) != nil {
		return nil, badRequest("ops must be an array")
	}
	if len(ops) == 0 {
		return nil, badRequest("ops can't be empty")
	}
	eb.Ops = make([]pop, len(ops))
	for i, raw := range ops {
		o, e := decodeOp(raw, i)
		if e != nil {
			return nil, e
		}
		eb.Ops[i] = o
	}
	return &eb, nil
}

// ---- authority and op rules (§16.2.2 checks 5 and 6, §16.2.3) ----

// applier applies one entry's ops in order to cur. The signer's authority comes from
// before, the state before the entry; every other rule is checked on cur, the state after
// the ops before it.
type applier struct {
	before *State
	cur    *State
	by     string
	ts     int64
	seq    uint64
	home   string
}

// signerPerms and signerLevel are the signer's, on the state before the entry.
func (a *applier) signerPerms() Perms {
	if a.before == nil {
		return All
	}
	return a.before.PermsOf(a.by)
}

func (a *applier) signerLevel() int {
	if a.before == nil {
		return math.MaxInt
	}
	return a.before.Level(a.by)
}

func (a *applier) isOwner() bool { return a.before == nil || a.before.Owner == a.by }

// rankBelow: a role ranks below the signer when its rank is less than the signer's level.
func (a *applier) rankBelow(rank int) bool { return rank < a.signerLevel() }

// memberBelow: a member ranks below the signer when the member's level is less than the
// signer's. Nobody ranks below themselves, and nobody outranks the owner.
func (a *applier) memberBelow(id string) bool {
	return id != a.by && a.cur.Level(id) < a.signerLevel()
}

// authority is check 5 for what depends only on the signer and the ops' kinds: the signer
// isn't banned, the entry has at most 256 ops, and the signer holds the permission each op
// needs at all. What also depends on an op's target (ranks, a code's creator) is checked
// with that op's rules, in apply.
func (a *applier) authority(ops []pop) *Error {
	b := a.before
	if b.BannedIDs[a.by] || (a.by != b.Owner && b.domainBanned(a.home)) {
		return notAllowed("the signer is banned")
	}
	if len(ops) > MaxOps {
		return notAllowed("an entry has at most 256 ops")
	}
	p := a.signerPerms()
	for _, o := range ops {
		var need Perms
		switch o.Op {
		case "set-name", "set-settings", "add-role", "edit-role", "remove-role", "add-channel",
			"edit-channel", "remove-channel", "order-channels", "ban", "unban":
			need = Administrate
		case "add-code":
			need = Invite
		case "timeout":
			need = Moderate
		case "transfer-ownership", "set-home":
			if !a.isOwner() {
				return notAllowed(o.Op + " is the owner's")
			}
		case "assign-roles":
			if p&(Administrate|Moderate) == 0 && o.Member != a.by {
				return notAllowed("assign-roles needs administrate, or moderate to clear a member's roles")
			}
		}
		if p&need != need {
			return notAllowed(o.Op + " needs a permission the signer doesn't have")
		}
	}
	return nil
}

// validRoleList checks a see or write list: ascending, each role once, each current, and
// a list containing 0 exactly [0] (§16.2.3).
func (a *applier) validRoleList(list []uint64) bool {
	if len(list) == 0 {
		return false
	}
	if slices.Contains(list, everyoneRole) {
		return len(list) == 1
	}
	for i, r := range list {
		if i > 0 && r <= list[i-1] {
			return false
		}
		if a.cur.Roles[r] == nil {
			return false
		}
	}
	return true
}

// grants reports whether the signer has every permission in p.
func (a *applier) grants(p Perms) bool { return a.signerPerms()&p == p }

func (a *applier) apply(o *pop, server string, mode Mode) (Op, *Error) {
	c := a.cur
	out := Op{Op: o.Op}
	switch o.Op {
	case "create":
		switch {
		case !validName(o.Name):
			return out, invalid("the community's name breaks the name rules")
		case o.hasDesc && !validDesc(o.Desc):
			return out, invalid("the description breaks the description rules")
		case o.dupPerms:
			return out, invalid("everyone lists a permission twice")
		case o.Everyone&^(Talk|Invite) != 0:
			return out, invalid("everyone can hold only talk and invite")
		case mode == Append && o.Server != server:
			return out, invalid("create must name this community server")
		}
		c.Name, c.Desc, c.Public, c.Approval = o.Name, o.Desc, o.Public, o.Approval
		c.Owner, c.Server, c.Everyone = a.by, o.Server, o.Everyone
		out.Server, out.Public = o.Server, o.Public

	case "set-name":
		if !validName(o.Name) {
			return out, invalid("the community's name breaks the name rules")
		}
		if o.hasDesc && !validDesc(o.Desc) {
			return out, invalid("the description breaks the description rules")
		}
		c.Name, c.Desc = o.Name, o.Desc

	case "set-settings":
		c.Public, c.Approval = o.Public, o.Approval
		if !o.Public {
			for k, cd := range c.Codes {
				if cd.Public {
					delete(c.Codes, k)
				}
			}
		}
		out.Public = o.Public

	case "add-role":
		out.ID = o.ID
		if !a.rankBelow(o.Rank) {
			return out, notAllowed("the role must rank below the signer")
		}
		if !a.grants(o.Perms) {
			return out, notAllowed("a role can't be given a permission the signer doesn't have")
		}
		if len(c.Roles) >= MaxRoles {
			return out, notAllowed("a community has at most 20 roles besides everyone")
		}
		switch {
		case o.ID != c.LastRole+1:
			return out, invalid("a new role's id is one more than the highest used")
		case o.dupPerms:
			return out, invalid("perms lists a permission twice")
		case c.rankTaken(o.Rank, 0):
			return out, invalid("another role has that rank")
		}
		c.Roles[o.ID] = &Role{ID: o.ID, Rank: o.Rank, Perms: o.Perms, HasName: true, HasColor: o.color.present}
		c.LastRole = o.ID

	case "edit-role":
		out.ID = o.ID
		if o.members == 0 {
			return out, badRequest("edit-role needs a member besides op and id")
		}
		if o.ID == everyoneRole {
			switch {
			case o.hasRank || o.name.present || o.color.present:
				return out, invalid("everyone's edit-role carries only perms")
			case o.dupPerms:
				return out, invalid("perms lists a permission twice")
			case o.Perms&^(Talk|Invite) != 0:
				return out, invalid("everyone can hold only talk and invite")
			case !a.grants(o.Perms &^ c.Everyone):
				return out, notAllowed("a role can't be given a permission the signer doesn't have")
			}
			c.Everyone = o.Perms
			break
		}
		r := c.Roles[o.ID]
		if r == nil {
			return out, invalid("no such role")
		}
		nameOnly := !o.hasRank && !o.hasPerms
		if !nameOnly {
			newRank := r.Rank
			if o.hasRank {
				newRank = o.Rank
			}
			if !a.rankBelow(r.Rank) || !a.rankBelow(newRank) {
				return out, notAllowed("the role must rank below the signer before and after the edit")
			}
			if o.hasPerms && !a.grants(o.Perms&^r.Perms) {
				return out, notAllowed("a role can't be given a permission the signer doesn't have")
			}
		}
		if o.dupPerms {
			return out, invalid("perms lists a permission twice")
		}
		if o.hasRank && c.rankTaken(o.Rank, o.ID) {
			return out, invalid("another role has that rank")
		}
		if o.hasRank {
			r.Rank = o.Rank
		}
		if o.hasPerms {
			r.Perms = o.Perms
		}
		if o.name.present {
			r.HasName = true
		}
		if o.color.present {
			r.HasColor = !o.color.null
		}

	case "remove-role":
		out.ID = o.ID
		r := c.Roles[o.ID]
		if r == nil {
			return out, invalid("no such role")
		}
		if !a.rankBelow(r.Rank) {
			return out, notAllowed("the role must rank below the signer")
		}
		for _, id := range c.Order {
			ch := c.Channels[id]
			ch.See = slices.DeleteFunc(ch.See, func(x uint64) bool { return x == o.ID })
			ch.Write = slices.DeleteFunc(ch.Write, func(x uint64) bool { return x == o.ID })
			if len(ch.See) == 0 || len(ch.Write) == 0 {
				return out, invalid("removing the role would leave a channel's see or write empty")
			}
		}
		for m, roles := range c.Assigned {
			roles = slices.DeleteFunc(roles, func(x uint64) bool { return x == o.ID })
			if len(roles) == 0 {
				delete(c.Assigned, m)
			} else {
				c.Assigned[m] = roles
			}
		}
		delete(c.Roles, o.ID)

	case "assign-roles":
		out.Member, out.Roles = o.Member, slices.Clone(o.Roles)
		for i, r := range o.Roles {
			if r == everyoneRole || c.Roles[r] == nil || (i > 0 && r <= o.Roles[i-1]) {
				return out, invalid("roles must be ascending current roles, without 0")
			}
		}
		held := c.Assigned[o.Member]
		selfRemoval := o.Member == a.by && isSubset(o.Roles, held)
		kick := len(o.Roles) == 0 && a.signerPerms()&Moderate != 0 && a.memberBelow(o.Member)
		if !selfRemoval && !kick {
			if a.signerPerms()&Administrate == 0 {
				return out, notAllowed("assign-roles needs administrate")
			}
			if o.Member != a.by && !a.memberBelow(o.Member) {
				return out, notAllowed("the member must rank below the signer")
			}
			var added Perms
			for _, r := range symmetricDiff(held, o.Roles) {
				if !a.rankBelow(c.Roles[r].Rank) {
					return out, notAllowed("every role that changes must rank below the signer")
				}
				if slices.Contains(o.Roles, r) {
					added |= c.Roles[r].Perms
				}
			}
			if !a.grants(added) {
				return out, notAllowed("a role added can't have a permission the signer doesn't have")
			}
		}
		if len(o.Roles) == 0 {
			delete(c.Assigned, o.Member)
		} else {
			c.Assigned[o.Member] = slices.Clone(o.Roles)
		}

	case "add-channel":
		out.ID, out.See, out.SeeSet = o.ID, slices.Clone(o.See), true
		if len(c.Channels) >= MaxChannels {
			return out, notAllowed("a community has at most 100 channels")
		}
		if o.Kind == "voice" && (o.Max < 1 || o.Max > MaxVoice || o.Cast < 1 || o.Cast > MaxCast) {
			return out, notAllowed("a voice channel holds 1 to 64 people, and 1 to 4 casting")
		}
		switch {
		case o.ID != c.LastChannel+1:
			return out, invalid("a new channel's id is one more than the highest used")
		case !a.validRoleList(o.See) || !a.validRoleList(o.Write):
			return out, invalid("see and write must be ascending current roles, or [0]")
		}
		ch := &Channel{ID: o.ID, Kind: o.Kind, See: slices.Clone(o.See), Write: slices.Clone(o.Write), HasTopic: o.topic.present}
		if o.Kind == "text" {
			ch.History, ch.Slow = o.History, o.Slow
		} else {
			ch.Max, ch.Cast = int(o.Max), int(o.Cast)
		}
		c.Channels[o.ID] = ch
		c.Order = append(c.Order, o.ID)
		c.LastChannel = o.ID

	case "edit-channel":
		out.ID = o.ID
		if o.members == 0 {
			return out, badRequest("edit-channel needs a member besides op and id")
		}
		ch := c.Channels[o.ID]
		if ch == nil {
			return out, invalid("no such channel")
		}
		if (o.hasMax && (o.Max < 1 || o.Max > MaxVoice)) || (o.hasCast && (o.Cast < 1 || o.Cast > MaxCast)) {
			return out, notAllowed("a voice channel holds 1 to 64 people, and 1 to 4 casting")
		}
		switch {
		case ch.Kind == "text" && (o.hasMax || o.hasCast):
			return out, invalid("max and cast are for voice channels")
		case ch.Kind == "voice" && (o.hasHistory || o.hasSlow):
			return out, invalid("history and slow are for text channels")
		case o.hasSee && !a.validRoleList(o.See), o.hasWrt && !a.validRoleList(o.Write):
			return out, invalid("see and write must be ascending current roles, or [0]")
		}
		if o.hasSee && !slices.Equal(o.See, ch.See) {
			keepsTopic := ch.HasTopic && !(o.topic.present && o.topic.null)
			if !o.name.present || (keepsTopic && !o.topic.present) {
				return out, invalid("an edit that changes see also carries name, and topic if the channel keeps one")
			}
			ch.See = slices.Clone(o.See)
			out.See, out.SeeSet = slices.Clone(o.See), true
		}
		if o.hasWrt {
			ch.Write = slices.Clone(o.Write)
		}
		if o.topic.present {
			ch.HasTopic = !o.topic.null
		}
		if o.hasHistory {
			ch.History = o.History
		}
		if o.hasSlow {
			ch.Slow = o.Slow
		}
		if o.hasMax {
			ch.Max = int(o.Max)
		}
		if o.hasCast {
			ch.Cast = int(o.Cast)
		}

	case "remove-channel":
		out.ID = o.ID
		if c.Channels[o.ID] == nil {
			return out, invalid("no such channel")
		}
		delete(c.Channels, o.ID)
		c.Order = slices.DeleteFunc(c.Order, func(x uint64) bool { return x == o.ID })

	case "order-channels":
		if len(o.IDs) != len(c.Channels) {
			return out, invalid("order-channels lists every current channel once")
		}
		seen := map[uint64]bool{}
		for _, id := range o.IDs {
			if c.Channels[id] == nil || seen[id] {
				return out, invalid("order-channels lists every current channel once")
			}
			seen[id] = true
		}
		c.Order = slices.Clone(o.IDs)

	case "add-code":
		sum := sha256.Sum256(o.Key)
		out.Key, out.Code, out.Public = bytes.Clone(o.Key), sum[:], o.Public
		if o.hasUses && (o.Uses < 1 || o.Uses > MaxCodeUses) {
			return out, notAllowed("a code allows 1 to 1,000 uses")
		}
		k := hex.EncodeToString(sum[:])
		switch {
		case c.UsedKeys[k]:
			return out, invalid("that key was already used by a code")
		case !o.Public && (!o.hasExp || !o.hasUses):
			return out, invalid("a code that isn't public has exp and uses")
		case o.hasExp && o.Exp <= a.ts:
			return out, invalid("exp must be later than the entry's ts")
		case o.Public && !c.Public:
			return out, invalid("public codes are allowed only while the public setting is on")
		}
		c.UsedKeys[k] = true
		c.Codes[k] = &Code{Key: bytes.Clone(o.Key), Hash: sum[:], Exp: o.Exp, Uses: int(o.Uses), Public: o.Public, Creator: a.by, Seq: a.seq}

	case "revoke-code":
		out.Code = bytes.Clone(o.Code)
		k := hex.EncodeToString(o.Code)
		cd := c.Codes[k]
		if cd == nil {
			return out, invalid("no such code")
		}
		if cd.Creator != a.by && a.signerPerms()&Administrate == 0 {
			return out, notAllowed("only the code's creator or an administrator revokes it")
		}
		delete(c.Codes, k)

	case "ban":
		out.Member, out.Domain = o.Member, o.Domain
		if o.Member != "" {
			if !a.memberBelow(o.Member) {
				return out, notAllowed("the member must rank below the signer")
			}
			if c.Owner == o.Member || c.BannedIDs[o.Member] {
				return out, invalid("can't ban the owner, or someone already banned")
			}
			c.BannedIDs[o.Member] = true
			delete(c.Assigned, o.Member)
			delete(c.Timeouts, o.Member)
		} else {
			if c.BannedDomains[o.Domain] {
				return out, invalid("that domain is already banned")
			}
			c.BannedDomains[o.Domain] = true
		}

	case "unban":
		out.Member, out.Domain = o.Member, o.Domain
		if o.Member != "" {
			if !c.BannedIDs[o.Member] {
				return out, invalid("no such ban")
			}
			delete(c.BannedIDs, o.Member)
		} else {
			if !c.BannedDomains[o.Domain] {
				return out, invalid("no such ban")
			}
			delete(c.BannedDomains, o.Domain)
		}

	case "timeout":
		out.Member, out.Until = o.Member, o.Until
		if !a.memberBelow(o.Member) {
			return out, notAllowed("the member must rank below the signer")
		}
		if o.Until > a.ts+MaxTimeout {
			return out, notAllowed("a timeout lasts at most 7 days")
		}
		if o.Until < a.ts {
			return out, invalid("until must be from the entry's ts")
		}
		if o.Until == a.ts {
			delete(c.Timeouts, o.Member)
		} else {
			c.Timeouts[o.Member] = o.Until
		}

	case "transfer-ownership":
		out.To = o.To
		if o.To == c.Owner || c.BannedIDs[o.To] {
			return out, invalid("the new owner can't be the owner, or banned")
		}
		c.Owner = o.To

	case "set-home":
		out.Server = o.Server
		if o.Server == c.Server {
			return out, invalid("set-home names a community server other than the current one")
		}
		c.Server = o.Server
		clear(c.Codes)
	}
	return out, nil
}

// rankTaken reports whether a current role other than except has rank.
func (st *State) rankTaken(rank int, except uint64) bool {
	for id, r := range st.Roles {
		if id != except && r.Rank == rank {
			return true
		}
	}
	return false
}

func isSubset(a, b []uint64) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// symmetricDiff lists the roles in exactly one of a and b.
func symmetricDiff(a, b []uint64) []uint64 {
	var out []uint64
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			out = append(out, x)
		}
	}
	return out
}
