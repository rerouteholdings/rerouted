package sfu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

func loopbackOnly(ip net.IP) bool { return ip.IsLoopback() }

// NewVoice, if set, makes the SFU the tests use instead of New: TestThroughSFUProcess
// (ipc_test.go) puts rerouted-sfu here.
var NewVoice func(t *testing.T, cfg Config) Voice

func newTestSFU(t *testing.T, cfg Config) Voice {
	t.Helper()
	cfg.Loopback, cfg.IPFilter = true, loopbackOnly
	if testing.Verbose() {
		cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	if NewVoice != nil {
		return NewVoice(t, cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return Local(s)
}

// clientAPI is a device's WebRTC stack: the codecs SPEC §15.3 names, loopback only.
func clientAPI(t *testing.T) *webrtc.API {
	t.Helper()
	me := &webrtc.MediaEngine{}
	fb := []webrtc.RTCPFeedback{{Type: "nack"}, {Type: "nack", Parameter: "pli"}}
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: opusCap, PayloadType: 111}, webrtc.RTPCodecTypeAudio); err != nil {
		t.Fatal(err)
	}
	h := h264Cap
	h.RTCPFeedback = fb
	if err := me.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: h, PayloadType: 102}, webrtc.RTPCodecTypeVideo); err != nil {
		t.Fatal(err)
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		t.Fatal(err)
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetIPFilter(loopbackOnly)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	return webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se))
}

type recv struct {
	video   bool
	payload []byte
}

// client is a device in a voice channel.
type client struct {
	t      *testing.T
	name   string
	room   VoiceRoom
	key    string
	pc     *webrtc.PeerConnection
	tracks map[string]*webrtc.TrackLocalStaticRTP // voice, audio, video
	video  *webrtc.RTPSender
	got    chan recv
	plis   atomic.Int32
	manual chan string // with manual, the SFU's offers wait here instead of being answered
	stop   chan struct{}

	async   sync.WaitGroup
	closing bool // under mu

	mu        sync.Mutex
	joined    bool
	pending   []webrtc.ICECandidateInit
	remoteVid []uint32 // SSRCs of video tracks received
}

func newClient(t *testing.T, api *webrtc.API, room VoiceRoom, name string, casts bool) *client {
	t.Helper()
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, name: name, room: room, key: name, pc: pc, tracks: map[string]*webrtc.TrackLocalStaticRTP{}, got: make(chan recv, 4096), stop: make(chan struct{})}
	t.Cleanup(func() {
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()
		close(c.stop)
		c.async.Wait()
		pc.Close()
	})
	kinds := []string{srcVoice}
	if casts {
		kinds = append(kinds, srcAudio, srcVideo)
	}
	for _, k := range kinds {
		capab := opusCap
		if k == srcVideo {
			capab = h264Cap
		}
		tr, err := webrtc.NewTrackLocalStaticRTP(capab, name+"-"+k, name)
		if err != nil {
			t.Fatal(err)
		}
		x, err := pc.AddTransceiverFromTrack(tr, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendrecv})
		if err != nil {
			t.Fatal(err)
		}
		c.tracks[k] = tr
		sender := x.Sender()
		if k == srcVideo {
			c.video = sender
		}
		go func() {
			for {
				pkts, _, err := sender.ReadRTCP()
				if err != nil {
					return
				}
				for _, p := range pkts {
					if _, ok := p.(*rtcp.PictureLossIndication); ok && k == srcVideo {
						c.plis.Add(1)
					}
				}
			}
		}()
	}
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		video := tr.Kind() == webrtc.RTPCodecTypeVideo
		if video {
			c.mu.Lock()
			c.remoteVid = append(c.remoteVid, uint32(tr.SSRC()))
			c.mu.Unlock()
		}
		for {
			p, _, err := tr.ReadRTP()
			if err != nil {
				return
			}
			select {
			case c.got <- recv{video, p.Payload}:
			default:
			}
		}
	})
	pc.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			return
		}
		init := cand.ToJSON()
		c.mu.Lock()
		if !c.joined {
			c.pending = append(c.pending, init)
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		c.trickle(init)
	})
	return c
}

func (c *client) trickle(init webrtc.ICECandidateInit) {
	b, _ := json.Marshal(iceJSON{Candidate: init.Candidate, SDPMid: init.SDPMid, SDPMLineIndex: init.SDPMLineIndex})
	if err := c.room.ICE(c.key, string(b)); err != nil {
		c.t.Errorf("%s: trickling a candidate: %v", c.name, err)
	}
}

// signal handles what the SFU sends this device: its offers and candidates.
func (c *client) signal(frame map[string]any) {
	data, _ := frame["data"].(string)
	switch frame["t"] {
	case "voice-sdp":
		if c.manual != nil {
			c.manual <- data
			return
		}
		c.mu.Lock()
		if c.closing {
			c.mu.Unlock()
			return
		}
		c.async.Add(1)
		c.mu.Unlock()
		go func() { defer c.async.Done(); c.answer(data) }()
	case "voice-ice":
		var ic iceJSON
		json.Unmarshal([]byte(data), &ic)
		c.pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: ic.Candidate, SDPMid: ic.SDPMid, SDPMLineIndex: ic.SDPMLineIndex})
	default:
		c.t.Errorf("%s: unexpected frame %v", c.name, frame)
	}
}

func (c *client) answer(data string) {
	var d sdpJSON
	if err := json.Unmarshal([]byte(data), &d); err != nil || d.Type != "offer" {
		c.t.Errorf("%s: SFU sent %q", c.name, data)
		return
	}
	if err := c.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: d.SDP}); err != nil {
		// An offer still on its way when the device left, and its connection closed.
		if errors.Is(err, webrtc.ErrConnectionClosed) || c.pc.ConnectionState() == webrtc.PeerConnectionStateClosed {
			return
		}
		c.t.Errorf("%s: SFU offer: %v", c.name, err)
		return
	}
	ans, err := c.pc.CreateAnswer(nil)
	if err == nil {
		err = c.pc.SetLocalDescription(ans)
	}
	if err != nil {
		if errors.Is(err, webrtc.ErrConnectionClosed) || c.pc.ConnectionState() == webrtc.PeerConnectionStateClosed {
			return // the device left meanwhile
		}
		c.t.Errorf("%s: answering: %v", c.name, err)
		return
	}
	if _, err := c.room.Remote(c.key, sdpText(c.pc.LocalDescription())); err != nil && !errors.Is(err, ErrNotIn) {
		c.t.Errorf("%s: sending the answer: %v", c.name, err)
	}
}

// join offers without waiting for candidates, and trickles them after.
func (c *client) join(visit uint32, max int, mayVoice bool) error {
	if c.pc.SignalingState() == webrtc.SignalingStateStable {
		offer, err := c.pc.CreateOffer(nil)
		if err != nil {
			return err
		}
		if err := c.pc.SetLocalDescription(offer); err != nil {
			return err
		}
	}
	ans, err := c.room.Join(Member{Key: c.key, ID: "tr:" + c.name, Dev: []byte(c.name), Visit: visit, Channel: 7}, sdpText(c.pc.LocalDescription()), max, mayVoice, c.signal)
	if err != nil {
		return err
	}
	var d sdpJSON
	if err := json.Unmarshal([]byte(ans), &d); err != nil || d.Type != "answer" {
		return fmt.Errorf("bad answer %q", ans)
	}
	if err := c.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: d.SDP}); err != nil {
		return err
	}
	c.mu.Lock()
	c.joined = true
	pending := c.pending
	c.pending = nil
	c.mu.Unlock()
	for _, p := range pending {
		c.trickle(p)
	}
	return nil
}

// send keeps sending packets on one of the device's sections, payload "<name>-<kind>-<n>",
// until the test ends.
func (c *client) send(kind string) {
	tr := c.tracks[kind]
	go func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for n := uint16(0); ; n++ {
			select {
			case <-c.stop:
				return
			case <-tick.C:
			}
			tr.WriteRTP(&rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: n, Timestamp: uint32(n) * 960, Marker: true},
				Payload: fmt.Appendf(nil, "%s-%s-%d", c.name, kind, n)})
		}
	}()
}

func (c *client) drain() {
	for {
		select {
		case <-c.got:
		default:
			return
		}
	}
}

// expect waits for a packet whose payload starts with prefix.
func (c *client) expect(prefix string) {
	c.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-c.got:
			if bytes.HasPrefix(r.payload, []byte(prefix)) {
				return
			}
		case <-deadline:
			c.t.Fatalf("%s: no %q packets", c.name, prefix)
		}
	}
}

// expectNone checks that no packet starting with prefix arrives for a while.
func (c *client) expectNone(prefix string, d time.Duration) {
	c.t.Helper()
	deadline := time.After(d)
	for {
		select {
		case r := <-c.got:
			if bytes.HasPrefix(r.payload, []byte(prefix)) {
				c.t.Fatalf("%s: got %q, which shouldn't be forwarded", c.name, r.payload)
			}
		case <-deadline:
			return
		}
	}
}

func mustJoin(t *testing.T, c *client, visit uint32, mayVoice bool) {
	t.Helper()
	if err := c.join(visit, 25, mayVoice); err != nil {
		t.Fatalf("%s joining: %v", c.name, err)
	}
}

func TestForwardBothWays(t *testing.T) {
	s := newTestSFU(t, Config{})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", true), newClient(t, api, room, "ravi", true)
	mustJoin(t, a, 1, true)
	mustJoin(t, b, 2, true)
	a.send(srcVoice)
	b.send(srcVoice)
	b.expect("kat-voice-")
	a.expect("ravi-voice-")
	if room.Len() != 2 || !room.Has("kat") {
		t.Fatalf("room has %d", room.Len())
	}
	st := room.State()
	if len(st) != 2 || st[0].ID != "tr:kat" || st[0].Visit != 1 || st[1].Visit != 2 || len(st[0].Cast) != 0 {
		t.Fatalf("state %+v", st)
	}
}

func TestVoiceGated(t *testing.T) {
	s := newTestSFU(t, Config{})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", true), newClient(t, api, room, "ravi", true)
	mustJoin(t, a, 1, false) // may only listen
	mustJoin(t, b, 2, true)
	a.send(srcVoice)
	b.send(srcVoice)
	a.expect("ravi-voice-") // listening works
	b.expectNone("kat-voice-", 700*time.Millisecond)
	room.SetVoice("kat", true)
	b.expect("kat-voice-")
	room.SetVoice("kat", false)
	time.Sleep(100 * time.Millisecond)
	b.drain()
	b.expectNone("kat-voice-", 500*time.Millisecond)
}

func TestCastLimitAndGating(t *testing.T) {
	s := newTestSFU(t, Config{})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b, c := newClient(t, api, room, "kat", true), newClient(t, api, room, "ravi", true), newClient(t, api, room, "mia", true)
	d := newClient(t, api, room, "theo", false) // offers the voice only
	mustJoin(t, a, 1, true)
	mustJoin(t, b, 2, true)
	mustJoin(t, c, 3, true)
	mustJoin(t, d, 4, true)
	a.send(srcVoice)
	a.send(srcAudio)
	a.send(srcVideo)
	b.expect("kat-voice-")
	d.expect("kat-voice-")
	b.expectNone("kat-audio-", 500*time.Millisecond) // not declared yet
	if err := room.SetCast("kat", []string{"audio", "video"}, 1); err != nil {
		t.Fatal(err)
	}
	b.expect("kat-audio-")
	b.expect("kat-video-")
	if err := room.SetCast("mia", []string{"video"}, 1); !errors.Is(err, ErrCastLimit) {
		t.Fatalf("second caster past a limit of 1: %v", err)
	}
	if err := room.SetCast("theo", []string{"audio"}, 4); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("a device without cast sections cast: %v", err)
	}
	if err := room.SetCast("kat", []string{"screen"}, 4); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("an unknown cast kind: %v", err)
	}
	// Only video now: its audio stops.
	if err := room.SetCast("kat", []string{"video"}, 1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	b.drain()
	b.expectNone("kat-audio-", 400*time.Millisecond)
	if st := room.State(); strings.Join(st[0].Cast, ",") != "video" {
		t.Fatalf("state %+v", st[0])
	}
	// Theo never receives a cast, and has no video section to receive one in.
	d.expectNone("kat-video-", 300*time.Millisecond)
	d.mu.Lock()
	nv := len(d.remoteVid)
	d.mu.Unlock()
	if nv != 0 {
		t.Fatal("a device without cast sections got video")
	}
	// Kat stops; Mia may start.
	if err := room.SetCast("kat", nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := room.SetCast("mia", []string{"video"}, 1); err != nil {
		t.Fatalf("after kat stopped: %v", err)
	}
	// Losing the right to speak ends a cast.
	room.SetVoice("mia", false)
	if st := room.State(); len(st[2].Cast) != 0 {
		t.Fatalf("mia still casting: %+v", st[2])
	}
	if err := room.SetCast("mia", []string{"video"}, 2); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("cast without voice: %v", err)
	}
}

func TestVisitsAndMax(t *testing.T) {
	s := newTestSFU(t, Config{})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", true), newClient(t, api, room, "ravi", true)
	mustJoin(t, a, 7, true)
	if err := b.join(7, 25, true); !errors.Is(err, ErrVisitInUse) {
		t.Fatalf("a visit ID in use: %v", err)
	}
	if err := b.join(8, 1, true); !errors.Is(err, ErrFull) {
		t.Fatalf("a full channel: %v", err)
	}
	if _, err := room.Join(Member{Key: "x", Visit: 9}, `{"type":"answer","sdp":"v=0"}`, 25, true, nil); !errors.Is(err, ErrBadSDP) {
		t.Fatalf("an answer for an offer: %v", err)
	}
	if _, err := room.Join(Member{Key: "x", Visit: 9}, `{"type":"offer","sdp":"nonsense"}`, 25, true, nil); !errors.Is(err, ErrBadSDP) {
		t.Fatalf("a bad offer: %v", err)
	}
	if room.Len() != 1 {
		t.Fatalf("failed joins left %d", room.Len())
	}
	mustJoin(t, b, 8, true)
	if err := room.NewVisit("ravi", 7); !errors.Is(err, ErrVisitInUse) {
		t.Fatalf("NewVisit to a visit in use: %v", err)
	}
	if err := room.NewVisit("ravi", 99); err != nil {
		t.Fatal(err)
	}
	if err := room.NewVisit("nobody", 5); !errors.Is(err, ErrNotIn) {
		t.Fatal(err)
	}
	if st := room.State(); st[1].Visit != 99 {
		t.Fatalf("state %+v", st)
	}
	// The visit ID is free again once its device leaves.
	if !room.Leave("kat") || room.Leave("kat") {
		t.Fatal("Leave")
	}
	if err := room.NewVisit("ravi", 7); err != nil {
		t.Fatal(err)
	}
	if _, err := room.Remote("kat", `{"type":"answer","sdp":"x"}`); !errors.Is(err, ErrNotIn) {
		t.Fatal(err)
	}
	if err := room.ICE("kat", `{"candidate":""}`); !errors.Is(err, ErrNotIn) {
		t.Fatal(err)
	}
}

// After someone leaves, the next one to join reuses their sections: no new offer, and
// the session description doesn't grow.
func TestLeaveFreesSections(t *testing.T) {
	s := newTestSFU(t, Config{})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", true), newClient(t, api, room, "ravi", true)
	mustJoin(t, a, 1, true)
	mustJoin(t, b, 2, true)
	b.send(srcVoice)
	a.expect("ravi-voice-")
	n := len(a.pc.GetTransceivers())
	room.Leave("ravi")
	time.Sleep(100 * time.Millisecond)
	a.drain()
	a.expectNone("ravi-voice-", 300*time.Millisecond)
	c := newClient(t, api, room, "mia", true)
	mustJoin(t, c, 3, true)
	c.send(srcVoice)
	a.expect("mia-voice-")
	if m := len(a.pc.GetTransceivers()); m != n {
		t.Fatalf("kat's sections went from %d to %d", n, m)
	}
}

func TestKeyframeRequestsForwarded(t *testing.T) {
	s := newTestSFU(t, Config{})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", true), newClient(t, api, room, "ravi", true)
	mustJoin(t, a, 1, true)
	mustJoin(t, b, 2, true)
	a.send(srcVideo)
	if err := room.SetCast("kat", []string{"video"}, 2); err != nil {
		t.Fatal(err)
	}
	b.expect("kat-video-")
	time.Sleep(400 * time.Millisecond) // past the requests the SFU makes on its own
	before := a.plis.Load()
	b.mu.Lock()
	ssrc := b.remoteVid[0]
	b.mu.Unlock()
	if err := b.pc.WriteRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: ssrc}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for a.plis.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("the caster never got the keyframe request")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A device's own offer that crosses the SFU's gets ErrGlare: the device answers the
// SFU's offer, then offers again, and that's answered.
func TestGlare(t *testing.T) {
	s := newTestSFU(t, Config{})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", true), newClient(t, api, room, "ravi", true)
	a.manual = make(chan string, 8)
	mustJoin(t, a, 1, true)
	mustJoin(t, b, 2, true)
	// The SFU's offer to Kat, adding Ravi's sections, waits unanswered.
	var pending string
	select {
	case pending = <-a.manual:
	case <-time.After(10 * time.Second):
		t.Fatal("no offer from the SFU")
	}
	crossing, err := a.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := room.Remote("kat", sdpText(&crossing)); !errors.Is(err, ErrGlare) {
		t.Fatalf("a crossing offer: %v", err)
	}
	a.answer(pending)
	a.async.Add(1)
	go func() {
		defer a.async.Done()
		for {
			select {
			case <-a.stop:
				return
			case o := <-a.manual:
				a.answer(o)
			}
		}
	}()
	b.send(srcVoice)
	a.expect("ravi-voice-")
	// Now Kat's own offer goes through.
	offer, err := a.pc.CreateOffer(nil)
	if err == nil {
		err = a.pc.SetLocalDescription(offer)
	}
	if err != nil {
		t.Fatal(err)
	}
	reply, err := room.Remote("kat", sdpText(a.pc.LocalDescription()))
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseSDP(reply, "answer")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.pc.SetRemoteDescription(d); err != nil {
		t.Fatal(err)
	}
	a.drain()
	a.expect("ravi-voice-")
	// An answer nobody asked for.
	if _, err := room.Remote("kat", sdpText(a.pc.CurrentRemoteDescription())); !errors.Is(err, ErrBadSDP) {
		t.Fatalf("an unexpected answer: %v", err)
	}
}

func TestOneUDPPort(t *testing.T) {
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	s := newTestSFU(t, Config{UDPPort: port})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", false), newClient(t, api, room, "ravi", false)
	mustJoin(t, a, 1, true)
	mustJoin(t, b, 2, true)
	a.send(srcVoice)
	b.expect("kat-voice-")
	if sd := b.pc.RemoteDescription().SDP; !strings.Contains(sd, fmt.Sprintf(" %d typ host", port)) {
		t.Fatalf("the SFU's candidates aren't on port %d", port)
	}
}

func TestGoneAndClose(t *testing.T) {
	var gone atomic.Value
	s := newTestSFU(t, Config{OnGone: func(room, key string) { gone.Store(room + "|" + key) }})
	api := clientAPI(t)
	room := s.Room("c/1")
	a, b := newClient(t, api, room, "kat", false), newClient(t, api, room, "ravi", false)
	mustJoin(t, a, 1, true)
	mustJoin(t, b, 2, true)
	a.send(srcVoice)
	b.expect("kat-voice-")
	a.pc.Close() // the device vanishes
	deadline := time.Now().Add(40 * time.Second)
	for room.Has("kat") {
		if time.Now().After(deadline) {
			t.Fatal("a dead connection stayed in the room")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// OnGone comes after the removal: in rerouted-sfu, as an event of its own.
	for g, _ := gone.Load().(string); g != "c/1|kat"; g, _ = gone.Load().(string) {
		if time.Now().After(deadline) {
			t.Fatalf("OnGone got %q", g)
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Close()
	if room.Len() != 0 {
		t.Fatal("Close left participants")
	}
	if _, err := room.Join(Member{Key: "x", Visit: 3}, `{"type":"offer","sdp":"v=0"}`, 25, true, nil); !errors.Is(err, ErrNotIn) {
		t.Fatal("joined a closed room")
	}
}

func TestPublicIPs(t *testing.T) {
	s := newTestSFU(t, Config{PublicIPs: []string{"198.51.100.7"}})
	room := s.Room("c/1")
	a := newClient(t, clientAPI(t), room, "kat", false)
	offer, err := a.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	ans, err := room.Join(Member{Key: "kat", Visit: 1}, sdpText(&offer), 25, true, a.signal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ans, "198.51.100.7") || strings.Contains(ans, "127.0.0.1") {
		t.Fatalf("host candidates not rewritten: %s", ans)
	}
}

// A device's answer or offer that reaches the SFU as it leaves, the connection closing
// under it, answers ErrNotIn, as it would a moment later: not ErrBadSDP.
func TestDescriptionAsItLeaves(t *testing.T) {
	s, err := New(Config{Loopback: true, IPFilter: loopbackOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	room := s.Room("c/1")
	a := newClient(t, clientAPI(t), room, "kat", false)
	mustJoin(t, a, 1, true)
	p := room.get("kat")
	if p == nil {
		t.Fatal("not in the room")
	}
	p.close()
	desc := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: "v=0"}
	if err := p.remoteAnswer(desc); !errors.Is(err, ErrNotIn) {
		t.Fatalf("an answer: %v", err)
	}
	desc.Type = webrtc.SDPTypeOffer
	if _, err := p.remoteOffer(desc); !errors.Is(err, ErrNotIn) {
		t.Fatalf("an offer: %v", err)
	}
}
