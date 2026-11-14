// Package sfu is the community server's selective forwarding unit for voice channels
// (SPEC §16.4, spec/api/community.md "Voice"), on Pion WebRTC.
//
// Each participant is one device with one PeerConnection to the SFU. Its offer has the
// three media sections of SPEC §15.3, all sendrecv: the voice (Opus), the cast's audio
// (Opus), and the cast's video (H.264 in name only: its RTP payloads are pieces of SFrame
// ciphertext, not RFC 6184). Media is SFrame-encrypted end to end, so the SFU never looks
// inside a payload: it forwards RTP packets, rewriting only what each outgoing stream needs
// (SSRC, payload type, sequence numbers, and timestamps).
//
// Packing. The device's own three sections only carry its media to the SFU. Everyone
// else's media reaches it in sendonly sections the SFU adds, called slots here: one slot
// carries one stream (one sender's voice, cast audio, or cast video) at a time. When a
// sender leaves, its slots on every receiver are freed and later reused for whoever joins
// next, with no new offer and no growing session description. A receiver tells senders
// apart by each frame's SFrame key ID, which starts with the visit ID (SPEC §16.4), never
// by section, so a slot changing hands needs no signaling. New slots need a new offer,
// which the SFU sends through the device's Signal.
package sfu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"
)

// Errors the Room methods return.
var (
	// ErrVisitInUse: another device in the room has that visit ID (SPEC §16.4).
	ErrVisitInUse = errors.New("sfu: visit ID already in use in this channel")
	// ErrFull: the room already has its maximum number of people.
	ErrFull = errors.New("sfu: voice channel full")
	// ErrBadSDP: a session description or ICE candidate that can't be used.
	ErrBadSDP = errors.New("sfu: bad session description")
	// ErrNotIn: the device isn't in this room.
	ErrNotIn = errors.New("sfu: not in this voice channel")
	// ErrCastLimit: as many people as the channel allows are casting already.
	ErrCastLimit = errors.New("sfu: too many people casting")
	// ErrGlare: the device's offer crossed one of the SFU's, which it should answer first.
	ErrGlare = errors.New("sfu: offers crossed; answer the SFU's offer, then offer again")
	// ErrNotAllowed: a cast from a device that may not speak, or that offered no cast
	// sections, or of a kind other than "audio" and "video".
	ErrNotAllowed = errors.New("sfu: can't cast")
)

// Source kinds: which of a device's three sections a stream came in on.
const (
	srcVoice = "voice"
	srcAudio = "audio" // the cast's audio
	srcVideo = "video" // the cast's video
)

// gatherWait bounds how long Join waits for its own ICE candidates, so they go out in
// the answer. With host candidates only, gathering ends at once.
const gatherWait = 3 * time.Second

// glareDelay is how long after answering a device's offer the SFU waits before sending an
// offer it held back meanwhile: the caller sends the answer after Remote returns, and it
// has to reach the device first.
const glareDelay = 250 * time.Millisecond

// Config sets up an SFU.
type Config struct {
	// UDPPort, if not 0, carries every connection's media on one UDP port, through a mux.
	// 0 uses an ephemeral port per connection.
	UDPPort int
	// PublicIPs, if set, replace the host candidates' addresses (1:1 NAT).
	PublicIPs []string
	// Loopback includes loopback candidates: for development and tests.
	Loopback bool
	// IPFilter, if set, keeps only the local addresses it returns true for.
	IPFilter func(net.IP) bool
	// OnGone, if set, hears about a participant whose connection failed or closed on its
	// own, after the SFU removed it. It isn't called for Leave.
	OnGone func(room, key string)
	Log    *slog.Logger
}

// SFU holds the rooms, one per voice channel.
type SFU struct {
	cfg Config
	api *webrtc.API
	mux ice.UDPMux

	mu     sync.Mutex
	rooms  map[string]*Room
	closed bool
}

// Signal sends a frame to a participant's device over its stream: voice-sdp and voice-ice.
type Signal func(frame map[string]any)

// Member is a device joining a room.
type Member struct {
	Key     string // unique per device connection
	ID      string // its identity
	Dev     []byte // its device key
	Visit   uint32
	Channel uint64 // the voice channel's ID, echoed in signaling frames
}

// Participant is one device in a room, as voice-state reports it.
type Participant struct {
	ID    string
	Dev   []byte
	Visit uint32
	Cast  []string
}

// New makes an SFU.
func New(cfg Config) (*SFU, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	me := &webrtc.MediaEngine{}
	fb := []webrtc.RTCPFeedback{{Type: "nack"}, {Type: "nack", Parameter: "pli"}, {Type: "ccm", Parameter: "fir"}}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1"},
		PayloadType:        111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, err
	}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f", RTCPFeedback: fb},
		PayloadType:        102,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, err
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return nil, err
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(cfg.Loopback)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	if cfg.IPFilter != nil {
		se.SetIPFilter(cfg.IPFilter)
	}
	if len(cfg.PublicIPs) > 0 {
		if err := se.SetICEAddressRewriteRules(webrtc.ICEAddressRewriteRule{External: cfg.PublicIPs, AsCandidateType: webrtc.ICECandidateTypeHost, Mode: webrtc.ICEAddressRewriteReplace}); err != nil {
			return nil, fmt.Errorf("sfu: public addresses: %w", err)
		}
	}
	s := &SFU{cfg: cfg, rooms: map[string]*Room{}}
	if cfg.UDPPort != 0 {
		opts := []ice.UDPMuxFromPortOption{}
		if cfg.Loopback {
			opts = append(opts, ice.UDPMuxFromPortWithLoopback())
		}
		if cfg.IPFilter != nil {
			opts = append(opts, ice.UDPMuxFromPortWithIPFilter(cfg.IPFilter))
		}
		mux, err := ice.NewMultiUDPMuxFromPort(cfg.UDPPort, opts...)
		if err != nil {
			return nil, fmt.Errorf("sfu: UDP port %d: %w", cfg.UDPPort, err)
		}
		se.SetICEUDPMux(mux)
		s.mux = mux
	}
	s.api = webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se))
	return s, nil
}

// Close ends every connection in every room.
func (s *SFU) Close() error {
	s.mu.Lock()
	s.closed = true
	rooms := s.rooms
	s.rooms = map[string]*Room{}
	s.mu.Unlock()
	for _, r := range rooms {
		r.closeAll()
	}
	if s.mux != nil {
		return s.mux.Close()
	}
	return nil
}

// Room returns the room for key, making it if it doesn't exist. Rooms are kept until
// Close: a community has at most 100 channels, and an empty room holds nothing.
func (s *SFU) Room(key string) *Room {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[key]
	if r == nil {
		r = &Room{sfu: s, key: key, peers: map[string]*peer{}}
		if s.closed {
			r.closed = true
		}
		s.rooms[key] = r
	}
	return r
}

// Room is one voice channel's participants.
type Room struct {
	sfu *SFU
	key string

	mu     sync.Mutex
	peers  map[string]*peer // by Member.Key
	order  []string         // join order, for State
	closed bool
}

// sdpJSON is a session description in the JSON shape SPEC §15.2 uses.
type sdpJSON struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

// iceJSON is an ICE candidate in the JSON shape SPEC §15.2 uses.
type iceJSON struct {
	Candidate     string  `json:"candidate"`
	SDPMid        *string `json:"sdpMid,omitempty"`
	SDPMLineIndex *uint16 `json:"sdpMLineIndex,omitempty"`
}

func parseSDP(data, want string) (webrtc.SessionDescription, error) {
	var d sdpJSON
	if err := json.Unmarshal([]byte(data), &d); err != nil || d.SDP == "" {
		return webrtc.SessionDescription{}, ErrBadSDP
	}
	switch {
	case want != "" && d.Type != want:
		return webrtc.SessionDescription{}, ErrBadSDP
	case d.Type == "offer":
		return webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: d.SDP}, nil
	case d.Type == "answer":
		return webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: d.SDP}, nil
	}
	return webrtc.SessionDescription{}, ErrBadSDP
}

func sdpText(d *webrtc.SessionDescription) string {
	b, _ := json.Marshal(sdpJSON{Type: d.Type.String(), SDP: d.SDP})
	return string(b)
}

// Join adds a device to the room with its offer, and returns the SFU's answer (JSON text
// {"type","sdp"}), with the SFU's ICE candidates in it. A device already in the room with
// the same Key is replaced. max is the room's limit on people (devices); mayVoice says
// whether its voice and casts are forwarded (SetVoice). Everyone else's media follows in a
// new offer through signal, once the connection is up.
func (r *Room) Join(m Member, offer string, max int, mayVoice bool, signal Signal) (string, error) {
	desc, err := parseSDP(offer, "offer")
	if err != nil {
		return "", err
	}
	p := &peer{room: r, key: m.Key, id: m.ID, dev: slices.Clone(m.Dev), visit: m.Visit, channel: m.Channel,
		signal: signal, mayVoice: mayVoice, done: make(chan struct{}), up: make(chan struct{}), mids: map[string]string{}, sources: map[string]*source{}}

	// Reserve the place and the visit ID before the slow part.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return "", ErrNotIn
	}
	old := r.peers[m.Key]
	n := len(r.peers)
	if old != nil {
		n--
	}
	for k, q := range r.peers {
		if k != m.Key && q.visit == m.Visit {
			r.mu.Unlock()
			return "", ErrVisitInUse
		}
	}
	if n >= max {
		r.mu.Unlock()
		return "", ErrFull
	}
	if old != nil {
		r.removeLocked(old)
	}
	r.peers[m.Key] = p
	r.order = append(r.order, m.Key)
	r.mu.Unlock()
	if old != nil {
		old.close()
	}

	answer, err := p.start(desc)
	if err != nil {
		r.mu.Lock()
		if r.peers[m.Key] == p {
			r.removeLocked(p)
		}
		r.mu.Unlock()
		p.close()
		return "", err
	}

	// Wire up the slots, both ways, with everyone ready.
	r.mu.Lock()
	if r.peers[m.Key] != p {
		r.mu.Unlock()
		p.close()
		return "", ErrNotIn // left while joining
	}
	p.ready = true
	var renegotiate []*peer
	mine := false
	for _, k := range r.order {
		q := r.peers[k]
		if q == p || !q.ready {
			continue
		}
		if q.attachAll(p) {
			renegotiate = append(renegotiate, q)
		}
		if p.attachAll(q) {
			mine = true
		}
	}
	r.mu.Unlock()
	for _, q := range renegotiate {
		go q.negotiate()
	}
	if mine {
		go p.negotiate() // waits for the connection: the device has the answer by then
	}
	return answer, nil
}

// NewVisit replaces a device's visit ID on the same connection, after its SFrame
// generation 255 (SPEC §16.4).
func (r *Room) NewVisit(key string, visit uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[key]
	if p == nil {
		return ErrNotIn
	}
	for k, q := range r.peers {
		if k != key && q.visit == visit {
			return ErrVisitInUse
		}
	}
	p.visit = visit
	return nil
}

// Leave removes a device from the room and closes its connection. Its slots on everyone
// else are freed for reuse. It reports whether the device was in the room.
func (r *Room) Leave(key string) bool {
	r.mu.Lock()
	p := r.peers[key]
	if p != nil {
		r.removeLocked(p)
	}
	r.mu.Unlock()
	if p == nil {
		return false
	}
	p.close()
	return true
}

// gone removes p after its connection failed or closed on its own.
func (r *Room) gone(p *peer) {
	r.mu.Lock()
	ok := r.peers[p.key] == p
	if ok {
		r.removeLocked(p)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	p.close()
	if r.sfu.cfg.OnGone != nil {
		r.sfu.cfg.OnGone(r.key, p.key)
	}
}

// removeLocked takes p out of the room and frees its slots on everyone else. r.mu is held.
func (r *Room) removeLocked(p *peer) {
	delete(r.peers, p.key)
	if i := slices.Index(r.order, p.key); i >= 0 {
		r.order = slices.Delete(r.order, i, i+1)
	}
	for _, s := range p.sourceList() {
		s.detachAll()
	}
}

func (r *Room) closeAll() {
	r.mu.Lock()
	r.closed = true
	ps := make([]*peer, 0, len(r.peers))
	for _, p := range r.peers {
		ps = append(ps, p)
		r.removeLocked(p)
	}
	r.mu.Unlock()
	for _, p := range ps {
		p.close()
	}
}

// Remote takes a voice-sdp from the device: an answer to the SFU's offer, which returns
// "", or an offer of its own, which returns the SFU's answer as JSON text. An offer that
// crosses the SFU's own pending offer gets ErrGlare: the device answers the SFU's first.
func (r *Room) Remote(key, data string) (string, error) {
	p := r.get(key)
	if p == nil {
		return "", ErrNotIn
	}
	desc, err := parseSDP(data, "")
	if err != nil {
		return "", err
	}
	if desc.Type == webrtc.SDPTypeAnswer {
		return "", p.remoteAnswer(desc)
	}
	return p.remoteOffer(desc)
}

// ICE adds a trickled ICE candidate from the device (JSON text {"candidate","sdpMid",
// "sdpMLineIndex"}). An empty candidate, meaning no more, is accepted and ignored.
func (r *Room) ICE(key, data string) error {
	p := r.get(key)
	if p == nil {
		return ErrNotIn
	}
	var c iceJSON
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return ErrBadSDP
	}
	if strings.TrimSpace(c.Candidate) == "" {
		return nil
	}
	if err := p.pc.Load().AddICECandidate(webrtc.ICECandidateInit{Candidate: c.Candidate, SDPMid: c.SDPMid, SDPMLineIndex: c.SDPMLineIndex}); err != nil {
		return ErrBadSDP
	}
	return nil
}

// SetVoice says whether a device's voice and casts are forwarded: while its identity may
// speak in the channel (a role in its write list, talk, and no timeout). Turning it off
// also ends its cast.
func (r *Room) SetVoice(key string, may bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[key]
	if p == nil {
		return
	}
	p.mayVoice = may
	if !may {
		p.cast = nil
	}
	p.gate()
}

// SetCast sets what a device is casting now: "audio", "video", both, or nothing. Past
// limit people casting at once, a new caster gets ErrCastLimit and nothing changes.
func (r *Room) SetCast(key string, kinds []string, limit int) error {
	var cast []string
	for _, k := range kinds {
		if (k != srcAudio && k != srcVideo) || slices.Contains(cast, k) {
			return ErrNotAllowed
		}
		cast = append(cast, k)
	}
	slices.Sort(cast)
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[key]
	if p == nil {
		return ErrNotIn
	}
	if len(cast) > 0 {
		if !p.mayVoice || !p.casts {
			return ErrNotAllowed
		}
		if len(p.cast) == 0 {
			n := 0
			for _, q := range r.peers {
				if q != p && len(q.cast) > 0 {
					n++
				}
			}
			if n >= limit {
				return ErrCastLimit
			}
		}
	}
	p.cast = cast
	p.gate()
	return nil
}

// State lists the room's participants, in the order they joined.
func (r *Room) State() []Participant {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Participant, 0, len(r.order))
	for _, k := range r.order {
		p := r.peers[k]
		cast := slices.Clone(p.cast)
		if cast == nil {
			cast = []string{}
		}
		out = append(out, Participant{ID: p.id, Dev: slices.Clone(p.dev), Visit: p.visit, Cast: cast})
	}
	return out
}

// Has reports whether a device is in the room.
func (r *Room) Has(key string) bool { return r.get(key) != nil }

// Len is how many devices are in the room.
func (r *Room) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.peers)
}

func (r *Room) get(key string) *peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.peers[key]
	if p == nil || p.pc.Load() == nil {
		return nil
	}
	return p
}
