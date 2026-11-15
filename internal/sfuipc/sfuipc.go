// Package sfuipc runs the voice SFU (internal/sfu) in a process of its own, rerouted-sfu,
// which rerouted reaches over a unix socket (REROUTED_SFU). WebRTC, with its UDP from
// anyone and its parsers of SDP, ICE, DTLS, SRTP, and RTP, then runs where there's nothing
// else: no database, no keys, no settings file, and no other network.
//
// rerouted sends requests, each with an ID, and rerouted-sfu answers each with the same ID,
// in any order: a join waits for ICE gathering, and other requests needn't wait for it. It
// also sends events, unasked: a frame for a device (Signal), and a participant gone
// (Config.OnGone). The first request is hello, with the SFU's settings; rerouted-sfu
// reads none of its own. One rerouted is served at a time, and when it disconnects, every
// room ends with it.
package sfuipc

import (
	"errors"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/sfu"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// maxMessage bounds a message: session descriptions are a few kilobytes.
const maxMessage = 1 << 20

type request struct {
	ID   uint64 `json:"id"`
	Op   string `json:"op"` // hello, join, visit, leave, remote, ice, voice, cast, state, has, len
	Room string `json:"room,omitempty"`
	Key  string `json:"key,omitempty"`

	// hello
	UDPPort   int      `json:"udp_port,omitempty"`
	PublicIPs []string `json:"public_ips,omitempty"`
	Loopback  bool     `json:"loopback,omitempty"`

	// join: the member, offer in Data; remote and ice: Data
	Who     string     `json:"who,omitempty"`
	Dev     wire.Bytes `json:"dev,omitempty"`
	Visit   uint32     `json:"visit,omitempty"`
	Channel uint64     `json:"channel,omitempty"`
	Data    string     `json:"data,omitempty"`
	Max     int        `json:"max,omitempty"`
	May     bool       `json:"may,omitempty"`

	// cast
	Kinds []string `json:"kinds,omitempty"`
	Limit int      `json:"limit,omitempty"`
}

// message is an answer to a request (ID not 0), or an event (Ev).
type message struct {
	ID    uint64        `json:"id,omitempty"`
	Err   string        `json:"err,omitempty"`
	Data  string        `json:"data,omitempty"`
	OK    bool          `json:"ok,omitempty"`
	N     int           `json:"n,omitempty"`
	State []participant `json:"state,omitempty"`

	Ev      string `json:"ev,omitempty"` // signal or gone
	Room    string `json:"room,omitempty"`
	Key     string `json:"key,omitempty"`
	T       string `json:"t,omitempty"`
	Channel uint64 `json:"channel,omitempty"`
}

type participant struct {
	ID    string     `json:"id"`
	Dev   wire.Bytes `json:"dev"`
	Visit uint32     `json:"visit"`
	Cast  []string   `json:"cast"`
}

// The sfu package's errors travel as codes, and come back as the same errors.
var codes = map[string]error{
	"visit-in-use": sfu.ErrVisitInUse,
	"full":         sfu.ErrFull,
	"bad-sdp":      sfu.ErrBadSDP,
	"not-in":       sfu.ErrNotIn,
	"cast-limit":   sfu.ErrCastLimit,
	"glare":        sfu.ErrGlare,
	"not-allowed":  sfu.ErrNotAllowed,
}

func errCode(err error) string {
	if err == nil {
		return ""
	}
	for c, e := range codes {
		if errors.Is(err, e) {
			return c
		}
	}
	return "error: " + err.Error()
}

func codeErr(code string) error {
	if code == "" {
		return nil
	}
	if e := codes[code]; e != nil {
		return e
	}
	return errors.New("rerouted-sfu: " + strings.TrimPrefix(code, "error: "))
}
