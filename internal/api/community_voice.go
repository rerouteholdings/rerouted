package api

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/sfu"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Voice channels (SPEC §16.4, spec/api/community.md, Voice). The community server runs an
// SFU (internal/sfu); signaling travels over each device's community stream. A device is in
// at most one voice channel at a time: joining another leaves the first. The SFU forwards a
// device's voice and casts only while its identity may speak there: a role in the channel's
// write list, talk, and no timeout. Who may join (seeing the channel, room for one more) and
// who may speak are decided here, from the community chain.

type voiceRooms struct {
	c   *community
	sfu *sfu.SFU // nil if it didn't start: voice-join answers unavailable
	mu  sync.Mutex
	at  map[string]*visitRec // devKey -> the visit the device is on
	// sent orders voice-state frames: each is built and queued under it, so a stream never
	// gets an older state after a newer one.
	sent sync.Mutex
}

type visitRec struct {
	id      string
	dev     []byte
	channel uint64
	visit   uint32
	may     bool
	s       *stream
}

func newVoiceRooms(c *community, s *sfu.SFU) *voiceRooms {
	return &voiceRooms{c: c, sfu: s, at: map[string]*visitRec{}}
}

func devKey(id string, dev []byte) string { return id + "|" + hex.EncodeToString(dev) }

func (v *voiceRooms) roomKey(ch uint64) string { return v.c.name + "|" + strconv.FormatUint(ch, 10) }

func (v *voiceRooms) room(ch uint64) *sfu.Room { return v.sfu.Room(v.roomKey(ch)) }

// mayVoice: a role in the channel's write list, talk, and no timeout.
func mayVoice(st *cchain.State, id string, ch *cchain.Channel) bool {
	return st.CanWrite(id, ch) && !st.TimedOut(id, now())
}

func (v *voiceRooms) fail(s *stream, code, msg string, ref []byte) {
	v.c.hs.sendFrame(s, map[string]any{"t": "error", "error": code, "msg": msg, "ref": wire.Raw(ref)})
}

// frame handles a voice frame from a device's stream.
func (v *voiceRooms) frame(ctx context.Context, s *stream, sess csess, t string, msg []byte) {
	var f struct {
		T       string   `json:"t"`
		Channel uint64   `json:"channel"`
		Visit   *uint64  `json:"visit,omitempty"`
		SDP     string   `json:"sdp,omitempty"`
		Data    string   `json:"data,omitempty"`
		Cast    []string `json:"cast,omitempty"`
	}
	if wire.Unmarshal(msg, &f) != nil || f.Channel == 0 {
		v.fail(s, wire.ErrCodeBadRequest, "", msg)
		return
	}
	if v.sfu == nil {
		v.fail(s, wire.ErrCodeUnavailable, "voice channels are off on this server", msg)
		return
	}
	key := devKey(sess.id, sess.dev)
	v.mu.Lock()
	rec := v.at[key]
	v.mu.Unlock()
	st := v.c.snapshot()
	if st == nil || v.c.moved(st) {
		v.fail(s, wire.ErrCodeNotAllowed, "", msg)
		return
	}
	ch := st.Channels[f.Channel]
	switch t {
	case "voice-join":
		if f.Visit == nil || *f.Visit > 0xFFFFFFFF {
			v.fail(s, wire.ErrCodeBadRequest, "visit", msg)
			return
		}
		visit := uint32(*f.Visit)
		if ch == nil || ch.Kind != "voice" {
			v.fail(s, wire.ErrCodeNotFound, "no such voice channel", msg)
			return
		}
		if ok, err := v.c.isMember(ctx, sess.id); err != nil || !ok || !st.CanSee(sess.id, ch) {
			v.fail(s, wire.ErrCodeNotAllowed, "", msg)
			return
		}
		if f.SDP == "" {
			// A new visit on the same connection, after SFrame generation 255 (SPEC §16.4).
			if rec == nil || rec.channel != f.Channel {
				v.fail(s, wire.ErrCodeBadRequest, "a voice-join without sdp is for the channel you're in", msg)
				return
			}
			if err := v.room(f.Channel).NewVisit(key, visit); err != nil {
				v.fail(s, sfuCode(err), "", msg)
				return
			}
			v.mu.Lock()
			rec.visit = visit
			v.mu.Unlock()
			v.c.hs.sendFrame(s, map[string]any{"t": "voice-joined", "channel": f.Channel, "visit": visit})
			v.broadcast(ctx, f.Channel)
			return
		}
		if rec != nil {
			v.leaveKey(ctx, key)
		}
		may := mayVoice(st, sess.id, ch)
		channel := f.Channel
		signal := func(frame map[string]any) { v.c.hs.sendFrame(s, frame) }
		answer, err := v.room(channel).Join(sfu.Member{Key: key, ID: sess.id, Dev: sess.dev, Visit: visit, Channel: channel}, f.SDP, ch.Max, may, signal)
		if err != nil {
			v.fail(s, sfuCode(err), err.Error(), msg)
			return
		}
		v.mu.Lock()
		v.at[key] = &visitRec{id: sess.id, dev: sess.dev, channel: channel, visit: visit, may: may, s: s}
		v.mu.Unlock()
		v.c.hs.sendFrame(s, map[string]any{"t": "voice-joined", "channel": channel, "visit": visit, "sdp": answer})
		v.broadcast(ctx, channel)
	case "voice-leave":
		if rec != nil && rec.channel == f.Channel {
			v.leaveKey(ctx, key)
		}
	case "voice-sdp", "voice-ice":
		if rec == nil || rec.channel != f.Channel {
			v.fail(s, wire.ErrCodeNotFound, "not in that voice channel", msg)
			return
		}
		if t == "voice-ice" {
			if err := v.room(f.Channel).ICE(key, f.Data); err != nil {
				v.fail(s, sfuCode(err), "", msg)
			}
			return
		}
		reply, err := v.room(f.Channel).Remote(key, f.Data)
		if err != nil {
			v.fail(s, sfuCode(err), err.Error(), msg)
			return
		}
		if reply != "" {
			v.c.hs.sendFrame(s, map[string]any{"t": "voice-sdp", "channel": f.Channel, "data": reply})
		}
	case "voice-cast":
		if rec == nil || rec.channel != f.Channel || ch == nil {
			v.fail(s, wire.ErrCodeNotFound, "not in that voice channel", msg)
			return
		}
		if !mayVoice(st, sess.id, ch) {
			v.fail(s, wire.ErrCodeNotAllowed, "you can't speak in this channel", msg)
			return
		}
		cast := f.Cast
		if cast == nil {
			cast = []string{}
		}
		if err := v.room(f.Channel).SetCast(key, cast, ch.Cast); err != nil {
			v.fail(s, sfuCode(err), err.Error(), msg)
			return
		}
		v.broadcast(ctx, f.Channel)
	}
}

// sfuCode maps an SFU error to an error code (spec/api/community.md).
func sfuCode(err error) string {
	switch {
	case errors.Is(err, sfu.ErrVisitInUse):
		return wire.ErrCodeAlreadyExists
	case errors.Is(err, sfu.ErrFull), errors.Is(err, sfu.ErrCastLimit), errors.Is(err, sfu.ErrNotAllowed):
		return wire.ErrCodeNotAllowed
	case errors.Is(err, sfu.ErrNotIn):
		return wire.ErrCodeNotFound
	case errors.Is(err, sfu.ErrBadSDP), errors.Is(err, sfu.ErrGlare):
		return wire.ErrCodeBadRequest
	}
	return wire.ErrCodeUnavailable
}

// stateFrame is a voice channel's voice-state, and how many are in it. v.sent is held.
func (v *voiceRooms) stateFrame(channel uint64) ([]byte, int, error) {
	in := []map[string]any{}
	if v.sfu != nil {
		for _, p := range v.room(channel).State() {
			cast := p.Cast
			if cast == nil {
				cast = []string{}
			}
			in = append(in, map[string]any{"id": p.ID, "dev": wire.Bytes(p.Dev), "visit": p.Visit, "cast": cast})
		}
	}
	frame, err := wire.Marshal(map[string]any{"t": "voice-state", "channel": channel, "in": in})
	return frame, len(in), err
}

// broadcast sends a voice channel's voice-state to every device registered for the group
// that carries it, with a stream open (spec/api/community.md).
func (v *voiceRooms) broadcast(ctx context.Context, channel uint64) {
	st := v.c.snapshot()
	if st == nil {
		return
	}
	ch := st.Channels[channel]
	if ch == nil {
		return
	}
	group, err := v.c.carrier(ctx, st, ch)
	if err != nil || group == nil {
		return
	}
	regs, err := v.c.st.Regs(ctx, group)
	if err != nil {
		return
	}
	v.sent.Lock()
	defer v.sent.Unlock()
	frame, _, err := v.stateFrame(channel)
	if err != nil {
		return
	}
	for _, reg := range regs {
		for _, s := range v.c.streams.of(reg.ID) {
			if string(s.device) == string(reg.Dev) {
				s.offer(frame, -1)
			}
		}
	}
}

// opened sends a stream that just opened, after its stored items, the voice-state of each
// voice channel with people in it whose group the device is registered for: it missed the
// changes before it connected (spec/api/community.md, GET stream). A channel with no
// voice-state is empty.
func (v *voiceRooms) opened(ctx context.Context, s *stream) {
	if v.sfu == nil {
		return
	}
	st := v.c.snapshot()
	if st == nil || v.c.moved(st) {
		return
	}
	registered := map[string]bool{} // group -> whether this device is registered for it
	for id, ch := range st.Channels {
		if ch.Kind != "voice" || v.room(id).Len() == 0 {
			continue
		}
		group, err := v.c.carrier(ctx, st, ch)
		if err != nil || group == nil {
			continue
		}
		ok, seen := registered[string(group)]
		if !seen {
			regs, err := v.c.st.Regs(ctx, group)
			if err != nil {
				continue
			}
			for _, reg := range regs {
				if reg.ID == s.id && string(reg.Dev) == string(s.device) {
					ok = true
				}
			}
			registered[string(group)] = ok
		}
		if !ok {
			continue
		}
		v.sent.Lock()
		if frame, n, err := v.stateFrame(id); err == nil && n > 0 {
			s.offer(frame, -1)
		}
		v.sent.Unlock()
	}
}

// leaveKey ends a device's visit, and tells the channel.
func (v *voiceRooms) leaveKey(ctx context.Context, key string) *visitRec {
	v.mu.Lock()
	rec := v.at[key]
	delete(v.at, key)
	v.mu.Unlock()
	if rec == nil || v.sfu == nil {
		return rec
	}
	v.room(rec.channel).Leave(key)
	v.broadcast(ctx, rec.channel)
	return rec
}

func (v *voiceRooms) leaveDevice(id string, dev []byte) {
	v.leaveKey(context.Background(), devKey(id, dev))
}

// keys lists the visits matching f.
func (v *voiceRooms) keys(f func(*visitRec) bool) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for k, rec := range v.at {
		if f(rec) {
			out = append(out, k)
		}
	}
	return out
}

func (v *voiceRooms) leaveIdentity(id string) {
	for _, k := range v.keys(func(r *visitRec) bool { return r.id == id }) {
		v.leaveKey(context.Background(), k)
	}
}

func (v *voiceRooms) closeChannel(channel uint64) {
	for _, k := range v.keys(func(r *visitRec) bool { return r.channel == channel }) {
		v.leaveKey(context.Background(), k)
	}
}

// gone: the SFU dropped a connection that failed or closed.
func (v *voiceRooms) gone(key string) {
	v.mu.Lock()
	rec := v.at[key]
	delete(v.at, key)
	v.mu.Unlock()
	if rec != nil {
		v.broadcast(context.Background(), rec.channel)
	}
}

// regate applies the chain to every visit: one that can't see its channel anymore leaves,
// and the rest are forwarded only while they may speak.
func (v *voiceRooms) regate(st *cchain.State) {
	if v.sfu == nil {
		return
	}
	type change struct {
		key string
		rec *visitRec
		may bool
	}
	var changes, leaves []change
	v.mu.Lock()
	for k, rec := range v.at {
		ch := st.Channels[rec.channel]
		if ch == nil || !st.CanSee(rec.id, ch) || v.c.moved(st) {
			leaves = append(leaves, change{k, rec, false})
			continue
		}
		if may := mayVoice(st, rec.id, ch); may != rec.may {
			rec.may = may
			changes = append(changes, change{k, rec, may})
		}
	}
	v.mu.Unlock()
	for _, l := range leaves {
		v.leaveKey(context.Background(), l.key)
	}
	for _, c := range changes {
		v.room(c.rec.channel).SetVoice(c.key, c.may)
		v.broadcast(context.Background(), c.rec.channel)
	}
}

// POST voice/move, for members with moderate who outrank id (spec/api/community.md).
func (c *community) voiceMove(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		ID string `json:"id"`
		To uint64 `json:"to"`
	}
	if !readBody(w, r, &req) {
		return
	}
	st := c.snapshot()
	if ch := st.Channels[req.To]; ch == nil || ch.Kind != "voice" {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "to isn't a voice channel")
		return
	}
	if req.ID == st.Owner || st.Level(req.ID) >= st.Level(sess.id) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "you don't outrank them")
		return
	}
	keys := c.voice.keys(func(rec *visitRec) bool { return rec.id == req.ID })
	if len(keys) == 0 {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "they aren't in a voice channel")
		return
	}
	for _, k := range keys {
		if rec := c.voice.leaveKey(r.Context(), k); rec != nil {
			c.hs.sendFrame(rec.s, map[string]any{"t": "voice-moved", "from": rec.channel, "to": req.To})
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
