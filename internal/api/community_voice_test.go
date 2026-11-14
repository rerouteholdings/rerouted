package api

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

// voiceOffer is a device's offer with the three media sections of SPEC §15.3, loopback only.
func voiceOffer(t *testing.T) string {
	t.Helper()
	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		t.Fatal(err)
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	api := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se))
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	for _, k := range []webrtc.RTPCodecType{webrtc.RTPCodecTypeAudio, webrtc.RTPCodecTypeAudio, webrtc.RTPCodecTypeVideo} {
		if _, err := pc.AddTransceiverFromKind(k, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendrecv}); err != nil {
			t.Fatal(err)
		}
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	done := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-done
	b, _ := json.Marshal(pc.LocalDescription())
	return string(b)
}

func sendFrame(t *testing.T, cl *ws.Client, f map[string]any) {
	t.Helper()
	b, _ := wire.Marshal(f)
	if err := cl.SendText(b); err != nil {
		t.Fatal(err)
	}
}

// voiceAnswer reads frames until a voice-joined or an error.
func voiceAnswer(t *testing.T, cl *ws.Client) map[string]any {
	t.Helper()
	for range 100 {
		f := readFrame(t, cl)
		if f["t"] == "voice-joined" || f["t"] == "error" {
			return f
		}
	}
	t.Fatal("no answer to voice-join")
	return nil
}

// Voice signaling over the stream (spec/api/community.md, Voice): visit IDs, the channel's
// size, who may see it, the cast limit, voice-state, and voice/move.
func TestCommunityVoice(t *testing.T) {
	if testing.Short() {
		t.Skip("WebRTC")
	}
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi, mia, lee := e.user("ravi"), e.user("mia"), e.user("lee")
	kat, m := joined(t, e, ravi, mia, lee)
	kat.mustAppend(m.ch, voiceChannel(1, 2, 1), voiceChannel(2, 25, 2),
		map[string]any{"op": "add-role", "id": 1, "rank": 5, "perms": []string{"talk"}, "name": sealed()},
		map[string]any{"op": "add-channel", "id": 3, "name": sealed(), "see": []uint64{1}, "write": []uint64{1}, "kind": "voice", "max": 5, "cast": 1})
	if e.srv.comm.sfu == nil {
		t.Fatal("the SFU didn't start")
	}
	kc, rc, mc, lc := kat.openStream(), ravi.openStream(), mia.openStream(), lee.openStream()

	sendFrame(t, kc, map[string]any{"t": "voice-join", "channel": 1, "visit": 7, "sdp": voiceOffer(t)})
	f := voiceAnswer(t, kc)
	if f["t"] != "voice-joined" || f["sdp"] == nil || fmt.Sprint(f["visit"]) != "7" {
		t.Fatalf("kat's join: %v", f)
	}
	var answer struct {
		Type string `json:"type"`
		SDP  string `json:"sdp"`
	}
	if json.Unmarshal([]byte(f["sdp"].(string)), &answer) != nil || answer.Type != "answer" || answer.SDP == "" {
		t.Fatalf("answer: %v", f["sdp"])
	}
	// Everyone registered for the members group hears voice-state.
	st := waitFrame(t, lc, "voice-state")
	if in := st["in"].([]any); len(in) != 1 || in[0].(map[string]any)["id"] != kat.id {
		t.Fatalf("voice-state: %v", st)
	}
	// The visit ID is taken in this channel.
	sendFrame(t, rc, map[string]any{"t": "voice-join", "channel": 1, "visit": 7, "sdp": voiceOffer(t)})
	if f := voiceAnswer(t, rc); f["t"] != "error" || f["error"] != wire.ErrCodeAlreadyExists {
		t.Fatalf("a visit ID in use: %v", f)
	}
	sendFrame(t, rc, map[string]any{"t": "voice-join", "channel": 1, "visit": 8, "sdp": voiceOffer(t)})
	if f := voiceAnswer(t, rc); f["t"] != "voice-joined" {
		t.Fatalf("ravi's join: %v", f)
	}
	// Full: the channel holds 2.
	sendFrame(t, mc, map[string]any{"t": "voice-join", "channel": 1, "visit": 9, "sdp": voiceOffer(t)})
	if f := voiceAnswer(t, mc); f["t"] != "error" || f["error"] != wire.ErrCodeNotAllowed {
		t.Fatalf("a full channel: %v", f)
	}
	// A channel mia can't see.
	sendFrame(t, mc, map[string]any{"t": "voice-join", "channel": 3, "visit": 9, "sdp": voiceOffer(t)})
	if f := voiceAnswer(t, mc); f["t"] != "error" || f["error"] != wire.ErrCodeNotAllowed {
		t.Fatalf("a channel she can't see: %v", f)
	}
	// One caster at a time in channel 1.
	sendFrame(t, kc, map[string]any{"t": "voice-cast", "channel": 1, "cast": []string{"video"}})
	for {
		f := readFrame(t, kc)
		if f["t"] == "error" {
			t.Fatalf("kat's cast: %v", f)
		}
		if f["t"] == "voice-state" && len(f["in"].([]any)) == 2 {
			if c := f["in"].([]any)[0].(map[string]any)["cast"].([]any); len(c) == 1 {
				break
			}
		}
	}
	sendFrame(t, rc, map[string]any{"t": "voice-cast", "channel": 1, "cast": []string{"audio"}})
	if f := waitFrame(t, rc, "error"); f["error"] != wire.ErrCodeNotAllowed {
		t.Fatalf("a second caster: %v", f)
	}
	// A new visit on the same connection, without sdp.
	sendFrame(t, rc, map[string]any{"t": "voice-join", "channel": 1, "visit": 10})
	if f := voiceAnswer(t, rc); f["t"] != "voice-joined" || fmt.Sprint(f["visit"]) != "10" {
		t.Fatalf("a new visit: %v", f)
	}
	// voice/move: rank applies.
	if c, _ := e.errOf("POST", "voice/move", ravi.tok, map[string]any{"id": kat.id, "to": 2}); c != 403 {
		t.Fatalf("a move without moderate: %d", c)
	}
	if c, _ := e.errOf("POST", "voice/move", kat.tok, map[string]any{"id": mia.id, "to": 2}); c != 404 {
		t.Fatalf("moving someone not in voice: %d", c)
	}
	if c := e.call("POST", "voice/move", kat.tok, map[string]any{"id": ravi.id, "to": 2}, nil); c != 204 {
		t.Fatalf("voice/move: %d", c)
	}
	if f := waitFrame(t, rc, "voice-moved"); fmt.Sprint(f["from"]) != "1" || fmt.Sprint(f["to"]) != "2" {
		t.Fatalf("voice-moved: %v", f)
	}
	// A timed-out member joins, and listens, but can't cast.
	kat.mustAppend(m.ch, map[string]any{"op": "timeout", "member": mia.id, "until": time.Now().Unix() + 600})
	sendFrame(t, mc, map[string]any{"t": "voice-join", "channel": 2, "visit": 11, "sdp": voiceOffer(t)})
	if f := voiceAnswer(t, mc); f["t"] != "voice-joined" {
		t.Fatalf("a timed-out member's join: %v", f)
	}
	sendFrame(t, mc, map[string]any{"t": "voice-cast", "channel": 2, "cast": []string{"audio"}})
	if f := waitFrame(t, mc, "error"); f["error"] != wire.ErrCodeNotAllowed {
		t.Fatalf("a timed-out member's cast: %v", f)
	}
	// Leaving, and a kick, end visits.
	sendFrame(t, kc, map[string]any{"t": "voice-leave", "channel": 1})
	room := e.srv.comm.byName["chat.test"].voice.room(1)
	for range 50 {
		if room.Len() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if room.Len() != 0 {
		t.Fatalf("%d left in channel 1", room.Len())
	}
	if c := e.call("POST", "members/kick", kat.tok, map[string]any{"id": mia.id}, nil); c != 204 {
		t.Fatalf("kick: %d", c)
	}
	if n := e.srv.comm.byName["chat.test"].voice.room(2).Len(); n != 0 {
		// ravi was moved out; mia was kicked.
		t.Fatalf("%d left in channel 2 after the kick", n)
	}
}
