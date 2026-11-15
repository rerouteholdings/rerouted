package sfu

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// The codecs the SFU offers in its slots, as registered in New.
var (
	opusCap = webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1"}
	h264Cap = webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"}
)

// keyframeGap is the least time between two keyframe requests the SFU sends one caster.
const keyframeGap = 200 * time.Millisecond

// peer is one device's connection to the SFU.
type peer struct {
	room    *Room
	key, id string
	dev     []byte
	channel uint64
	signal  Signal

	pc     atomic.Pointer[webrtc.PeerConnection]
	done   chan struct{} // closed by close
	up     chan struct{} // closed once ICE connects: the device has the SFU's answer
	once   sync.Once
	upOnce sync.Once

	// Under room.mu.
	visit    uint32
	mayVoice bool
	cast     []string
	ready    bool // its connection is set up and its slots wired

	mu      sync.Mutex        // mids, sources, joined
	mids    map[string]string // the device's own sections: mid -> source kind
	sources map[string]*source
	casts   bool // it offered both cast sections
	joined  bool // its answer was read: later candidates are trickled

	slotMu sync.Mutex
	slots  []*slot // the SFU's sendonly sections on this connection

	neg     sync.Mutex
	pending bool // an offer of the SFU's awaits the device's answer
	again   bool // something changed meanwhile: offer again after
}

// source is one of a device's incoming streams, forwarded to slots on everyone else.
type source struct {
	owner *peer
	kind  string // srcVoice, srcAudio, or srcVideo
	on    atomic.Bool
	gen   atomic.Uint32 // bumped each time forwarding turns on: outgoing streams rebase
	ssrc  atomic.Uint32 // the device's SSRC for it, once media arrives

	mu      sync.Mutex
	slots   []*slot
	lastPLI time.Time
}

// slot is one sendonly section the SFU added to a receiver's connection. It carries one
// source at a time, rewriting sequence numbers and timestamps so the stream stays
// continuous across a change of source or a pause.
type slot struct {
	owner  *peer
	video  bool
	clock  uint32
	track  *webrtc.TrackLocalStaticRTP
	sender *webrtc.RTPSender

	mu       sync.Mutex
	src      *source
	gen      uint32
	based    bool
	started  bool
	seqOff   uint16
	tsOff    uint32
	lastSeq  uint16
	lastTS   uint32
	lastWall time.Time
}

func (s *source) wantsVideo() bool { return s.kind == srcVideo }

// start makes the connection, takes the device's offer, and returns the answer.
func (p *peer) start(offer webrtc.SessionDescription) (string, error) {
	pc, err := p.room.sfu.api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return "", err
	}
	p.pc.Store(pc)
	select {
	case <-p.done:
		pc.Close()
		return "", ErrNotIn
	default:
	}
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		p.mu.Lock()
		joined := p.joined
		p.mu.Unlock()
		if !joined {
			return // it's in the answer
		}
		init := c.ToJSON()
		b, _ := jsonText(iceJSON{Candidate: init.Candidate, SDPMid: init.SDPMid, SDPMLineIndex: init.SDPMLineIndex})
		p.signal(map[string]any{"t": "voice-ice", "channel": p.channel, "data": b})
	})
	pc.OnICEConnectionStateChange(func(st webrtc.ICEConnectionState) {
		if st == webrtc.ICEConnectionStateConnected || st == webrtc.ICEConnectionStateCompleted {
			p.upOnce.Do(func() { close(p.up) })
		}
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			go p.room.gone(p)
		}
	})
	pc.OnTrack(p.onTrack)
	if err := pc.SetRemoteDescription(offer); err != nil {
		return "", ErrBadSDP
	}
	// The device's own sections, in order: the voice, then the cast's audio and video.
	audio, video := 0, 0
	p.mu.Lock()
	for _, tr := range pc.GetTransceivers() {
		switch tr.Kind() {
		case webrtc.RTPCodecTypeAudio:
			if audio == 0 {
				p.mids[tr.Mid()] = srcVoice
			} else if audio == 1 {
				p.mids[tr.Mid()] = srcAudio
			}
			audio++
		case webrtc.RTPCodecTypeVideo:
			if video == 0 {
				p.mids[tr.Mid()] = srcVideo
			}
			video++
		}
	}
	p.casts = audio >= 2 && video >= 1
	p.sources[srcVoice] = &source{owner: p, kind: srcVoice}
	if p.casts {
		p.sources[srcAudio] = &source{owner: p, kind: srcAudio}
		p.sources[srcVideo] = &source{owner: p, kind: srcVideo}
	} else {
		for mid, k := range p.mids {
			if k != srcVoice {
				delete(p.mids, mid)
			}
		}
	}
	p.mu.Unlock()
	if audio == 0 {
		return "", ErrBadSDP
	}
	p.room.mu.Lock()
	p.gate()
	p.room.mu.Unlock()

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return "", ErrBadSDP
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		return "", ErrBadSDP
	}
	select {
	case <-gathered:
	case <-time.After(gatherWait):
	case <-p.done:
		return "", ErrNotIn
	}
	p.mu.Lock()
	p.joined = true
	ld := pc.LocalDescription()
	p.mu.Unlock()
	if ld == nil {
		return "", ErrBadSDP
	}
	return sdpText(ld), nil
}

func jsonText(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// onTrack forwards one of the device's incoming streams.
func (p *peer) onTrack(t *webrtc.TrackRemote, rcv *webrtc.RTPReceiver) {
	pc := p.pc.Load()
	mid := ""
	for _, tr := range pc.GetTransceivers() {
		if tr.Receiver() == rcv {
			mid = tr.Mid()
			break
		}
	}
	p.mu.Lock()
	s := p.sources[p.mids[mid]]
	p.mu.Unlock()
	if s != nil {
		s.ssrc.Store(uint32(t.SSRC()))
		if s.on.Load() && s.wantsVideo() {
			s.requestKeyframe()
		}
	}
	for {
		pkt, _, err := t.ReadRTP()
		if err != nil {
			return
		}
		if s == nil || !s.on.Load() || len(pkt.Payload) == 0 {
			continue
		}
		s.forward(pkt)
	}
}

// gate sets which of the device's streams are forwarded: its voice while it may speak, and
// each cast kind it declared, too. room.mu is held.
func (p *peer) gate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for kind, s := range p.sources {
		on := p.mayVoice && (kind == srcVoice || slices.Contains(p.cast, kind))
		if on && !s.on.Load() {
			s.gen.Add(1)
			s.on.Store(true)
			if s.wantsVideo() {
				go s.requestKeyframe()
			}
		} else if !on {
			s.on.Store(false)
		}
	}
}

func (p *peer) sourceList() []*source {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*source, 0, len(p.sources))
	for _, k := range []string{srcVoice, srcAudio, srcVideo} {
		if s := p.sources[k]; s != nil {
			out = append(out, s)
		}
	}
	return out
}

// attachAll gives each of q's streams a slot on p's connection: a free one if there is
// one, else a new one. It reports whether p needs a new offer. room.mu is held.
func (p *peer) attachAll(q *peer) bool {
	p.mu.Lock()
	casts := p.casts
	p.mu.Unlock()
	added := false
	for _, s := range q.sourceList() {
		if s.kind != srcVoice && !casts {
			continue // a device that offered no cast sections never receives a cast (SPEC §15.3)
		}
		if p.attach(s) {
			added = true
		}
	}
	return added
}

// attach puts s on a slot of p's, and reports whether it had to add one.
func (p *peer) attach(s *source) bool {
	p.slotMu.Lock()
	defer p.slotMu.Unlock()
	video := s.wantsVideo()
	var sl *slot
	for _, c := range p.slots {
		c.mu.Lock()
		free := c.src == nil && c.video == video
		c.mu.Unlock()
		if free {
			sl = c
			break
		}
	}
	added := false
	if sl == nil {
		var err error
		if sl, err = p.addSlot(video); err != nil {
			p.room.sfu.cfg.Log.Warn("sfu: adding a section", "err", err)
			return false
		}
		p.slots = append(p.slots, sl)
		added = true
	}
	s.mu.Lock()
	sl.mu.Lock()
	sl.src, sl.based = s, false
	sl.mu.Unlock()
	s.slots = append(s.slots, sl)
	s.mu.Unlock()
	if video && s.on.Load() {
		go s.requestKeyframe()
	}
	return added
}

func (p *peer) addSlot(video bool) (*slot, error) {
	capab, clock := opusCap, uint32(48000)
	if video {
		capab, clock = h264Cap, 90000
	}
	var id [8]byte
	rand.Read(id[:])
	track, err := webrtc.NewTrackLocalStaticRTP(capab, "s"+hex.EncodeToString(id[:]), "sfu")
	if err != nil {
		return nil, err
	}
	tr, err := p.pc.Load().AddTransceiverFromTrack(track, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly})
	if err != nil {
		return nil, err
	}
	sl := &slot{owner: p, video: video, clock: clock, track: track, sender: tr.Sender()}
	go sl.readRTCP()
	return sl, nil
}

// readRTCP reads the receiver's feedback on a slot, as the interceptors need, and passes
// keyframe requests on to the slot's current source.
func (sl *slot) readRTCP() {
	for {
		pkts, _, err := sl.sender.ReadRTCP()
		if err != nil {
			return
		}
		for _, pkt := range pkts {
			switch pkt.(type) {
			case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
				sl.mu.Lock()
				src := sl.src
				sl.mu.Unlock()
				if src != nil && src.wantsVideo() {
					src.requestKeyframe()
				}
			}
		}
	}
}

// requestKeyframe asks the caster for a keyframe, at most once per keyframeGap.
func (s *source) requestKeyframe() {
	ssrc := s.ssrc.Load()
	if ssrc == 0 {
		return
	}
	s.mu.Lock()
	if time.Since(s.lastPLI) < keyframeGap {
		s.mu.Unlock()
		return
	}
	s.lastPLI = time.Now()
	s.mu.Unlock()
	if pc := s.owner.pc.Load(); pc != nil {
		pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: ssrc}})
	}
}

func (s *source) forward(pkt *rtp.Packet) {
	s.mu.Lock()
	slots := slices.Clone(s.slots)
	s.mu.Unlock()
	for _, sl := range slots {
		sl.write(s, pkt)
	}
}

// detachAll frees every slot s is on. Lock order: source, then slot.
func (s *source) detachAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sl := range s.slots {
		sl.mu.Lock()
		if sl.src == s {
			sl.src = nil
		}
		sl.mu.Unlock()
	}
	s.slots = nil
}

// write sends one of s's packets on the slot. The payload goes as it came: it's SFrame
// ciphertext. Header extensions were negotiated with the sender, not this receiver, so
// they're dropped, and the interceptors add this connection's own.
func (sl *slot) write(s *source, pkt *rtp.Packet) {
	sl.mu.Lock()
	if sl.src != s {
		sl.mu.Unlock()
		return
	}
	now := time.Now()
	if g := s.gen.Load(); !sl.based || sl.gen != g {
		if sl.started {
			sl.seqOff = sl.lastSeq + 1 - pkt.SequenceNumber
			d := uint32(now.Sub(sl.lastWall).Seconds() * float64(sl.clock))
			if d == 0 {
				d = 1
			}
			sl.tsOff = sl.lastTS + d - pkt.Timestamp
		} else {
			sl.seqOff, sl.tsOff, sl.started = 0, 0, true
			sl.lastSeq, sl.lastTS, sl.lastWall = pkt.SequenceNumber-1, pkt.Timestamp, now
		}
		sl.based, sl.gen = true, g
	}
	h := pkt.Header
	h.SequenceNumber += sl.seqOff
	h.Timestamp += sl.tsOff
	h.Extension, h.Extensions, h.ExtensionProfile = false, nil, 0
	h.Padding, h.PaddingSize = false, 0
	if int16(h.SequenceNumber-sl.lastSeq) > 0 {
		sl.lastSeq = h.SequenceNumber
	}
	if int32(h.Timestamp-sl.lastTS) > 0 {
		sl.lastTS, sl.lastWall = h.Timestamp, now
	}
	sl.mu.Unlock()
	sl.track.WriteRTP(&rtp.Packet{Header: h, Payload: pkt.Payload})
}

// negotiate sends the device a new offer with the SFU's current sections, once the
// connection is up. If an offer is already out, it goes again after the answer.
func (p *peer) negotiate() {
	select {
	case <-p.up:
	case <-p.done:
		return
	}
	p.neg.Lock()
	pc := p.pc.Load()
	if p.pending || pc.SignalingState() != webrtc.SignalingStateStable {
		p.again = true
		p.neg.Unlock()
		return
	}
	offer, err := pc.CreateOffer(nil)
	if err == nil {
		err = pc.SetLocalDescription(offer)
	}
	if err != nil {
		p.neg.Unlock()
		p.room.sfu.cfg.Log.Warn("sfu: making an offer", "err", err)
		return
	}
	p.pending, p.again = true, false
	ld := pc.LocalDescription()
	p.neg.Unlock()
	p.signal(map[string]any{"t": "voice-sdp", "channel": p.channel, "data": sdpText(ld)})
}

// remoteAnswer takes the device's answer to the SFU's offer. A bad one leaves the offer
// pending, so the device can answer it again.
func (p *peer) remoteAnswer(desc webrtc.SessionDescription) error {
	p.neg.Lock()
	defer p.neg.Unlock()
	pc := p.pc.Load()
	if p.left() {
		return ErrNotIn
	}
	if !p.pending {
		return ErrBadSDP
	}
	if err := pc.SetRemoteDescription(desc); err != nil {
		if p.left() {
			return ErrNotIn // it left while its answer was on its way
		}
		p.room.sfu.cfg.Log.Debug("sfu: a device's answer", "err", err)
		return ErrBadSDP
	}
	p.pending = false
	if p.again {
		p.again = false
		go p.negotiate()
	}
	return nil
}

// remoteOffer answers an offer from the device. The SFU is the impolite peer of WebRTC's
// perfect negotiation: an offer that crosses its own pending one gets ErrGlare, and the
// device, the polite peer, rolls its offer back, answers the SFU's, and offers again after.
// (Pion can't roll back a local offer.)
func (p *peer) remoteOffer(desc webrtc.SessionDescription) (string, error) {
	p.neg.Lock()
	defer p.neg.Unlock()
	pc := p.pc.Load()
	if p.left() {
		return "", ErrNotIn
	}
	if p.pending || pc.SignalingState() != webrtc.SignalingStateStable {
		return "", ErrGlare
	}
	if err := pc.SetRemoteDescription(desc); err != nil {
		if p.left() {
			return "", ErrNotIn
		}
		p.room.sfu.cfg.Log.Debug("sfu: a device's offer", "err", err)
		return "", ErrBadSDP
	}
	answer, err := pc.CreateAnswer(nil)
	if err == nil {
		err = pc.SetLocalDescription(answer)
	}
	if err != nil && p.left() {
		return "", ErrNotIn
	}
	if err != nil {
		// The offer is set and can't be rolled back: the connection can't go on.
		p.room.sfu.cfg.Log.Warn("sfu: answering a device's offer", "err", err)
		go p.room.gone(p)
		return "", ErrBadSDP
	}
	if p.again {
		p.again = false
		time.AfterFunc(glareDelay, p.negotiate)
	}
	return sdpText(pc.LocalDescription()), nil
}

// left reports whether the device has left: close ran, and its connection is closing.
// Session descriptions that fail on the closed connection then answer ErrNotIn, as they
// would a moment later, and not ErrBadSDP.
func (p *peer) left() bool {
	if p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// close ends the connection.
func (p *peer) close() {
	p.once.Do(func() {
		if p.done != nil {
			close(p.done)
		}
		if pc := p.pc.Load(); pc != nil {
			pc.Close()
		}
	})
}
