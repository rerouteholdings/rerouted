package keyd

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// What rerouted-keyd signs, and the checks each body must pass. Anything else is refused.
// The windows are those the protocol gives each object: a compromised rerouted can't make
// one that outlives it by more.
const (
	// maxSkew is fed.MaxSkew: how far an S2S request's ts may be from now (SPEC §8.3).
	maxSkew = 5 * 60
	// maxReservation is how far in the future a move reservation may expire: its 10
	// minutes (SPEC §6.6, §16.6), and the clock skew.
	maxReservation = 10*60 + maxSkew
)

var policy = map[string]func(h held, b []byte, now int64) error{
	// S2S requests (SPEC §8.3): from this server, now.
	"s2s": func(h held, b []byte, now int64) error {
		var r struct {
			From string `json:"from"`
			TS   int64  `json:"ts"`
		}
		if err := wire.Unmarshal(b, &r); err != nil {
			return err
		}
		if r.From != h.name {
			return fmt.Errorf("from %q, but this key is %s's", r.From, h.name)
		}
		return recent(r.TS, now)
	},
	// Commit receipts: this server as the hub, now.
	"commit-receipt": func(h held, b []byte, now int64) error {
		var r struct {
			Hub string `json:"hub"`
			TS  int64  `json:"ts"`
		}
		if err := wire.Unmarshal(b, &r); err != nil {
			return err
		}
		if r.Hub != h.name {
			return fmt.Errorf("hub %q, but this key is %s's", r.Hub, h.name)
		}
		return recent(r.TS, now)
	},
	// Move reservations (SPEC §6.6): for moving here, for 10 minutes.
	"move-reservation": reservation,
	// Community move reservations (SPEC §16.6): the same, for a community; composite only.
	"community-move-reservation": func(h held, b []byte, now int64) error {
		if h.v2 == nil {
			return errors.New("only a wire version 2 key signs it")
		}
		return reservation(h, b, now)
	},
}

func reservation(h held, b []byte, now int64) error {
	var r struct {
		Server string `json:"server"`
		Exp    int64  `json:"exp"`
	}
	if err := wire.Unmarshal(b, &r); err != nil {
		return err
	}
	if r.Server != h.name {
		return fmt.Errorf("server %q, but this key is %s's", r.Server, h.name)
	}
	if r.Exp <= now-maxSkew || r.Exp > now+maxReservation {
		return fmt.Errorf("it expires at %d, not within %d seconds of now (%d)", r.Exp, maxReservation, now)
	}
	return nil
}

func recent(ts, now int64) error {
	if ts > now+maxSkew || ts < now-maxSkew {
		return fmt.Errorf("ts %d is more than %d seconds from now (%d)", ts, maxSkew, now)
	}
	return nil
}

// check decides whether h may sign b as t.
func check(h held, t, b string, now int64) error {
	p := policy[t]
	if p == nil {
		return fmt.Errorf("%q isn't something a server signs with its own key", t)
	}
	// The exact bytes that get signed are canonical JSON: no second reading of them.
	if c, err := wire.Canonical([]byte(b)); err != nil || !bytes.Equal(c, []byte(b)) {
		return errors.New("the body isn't canonical JSON")
	}
	return p(h, []byte(b), now)
}
