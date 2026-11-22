package api

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// The homeserver is the clock (SPEC §8.4). Servers keep theirs synchronized; clients
// correct for the difference from their homeserver's. A timestamp too far off is refused
// with clock-skew, saying by how much and giving this server's time, and the operator
// hears about it in the log: when clients or peers are off the same way, it's this
// server's clock that's wrong.

// clockNotes rate-limits the clock lines in the log: one per kind per peer (or one for
// all clients) every 10 minutes, so a broken clock doesn't flood it. An incoming request's
// sender isn't verified when it's refused for its clock, so anyone can name any server.
// Notes older than 10 minutes are dropped, and past maxClockNotes peers, the rest share
// one note, so the record and the log stay bounded.
type clockNotes struct {
	mu        sync.Mutex
	last      map[string]time.Time
	nextSweep time.Time
}

const (
	clockNoteEvery = 10 * time.Minute
	maxClockNotes  = 256
	clockOverflow  = "others"
)

func (c *clockNotes) due(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.last == nil {
		c.last = map[string]time.Time{}
	}
	if now.After(c.nextSweep) || len(c.last) >= maxClockNotes {
		for k, t := range c.last {
			if now.Sub(t) >= clockNoteEvery {
				delete(c.last, k)
			}
		}
		c.nextSweep = now.Add(time.Minute)
	}
	if _, ok := c.last[key]; !ok && len(c.last) >= maxClockNotes {
		key = clockOverflow
	}
	if t, ok := c.last[key]; ok && now.Sub(t) < clockNoteEvery {
		return false
	}
	c.last[key] = now
	return true
}

// skewText says how far apart two clocks are, for people: "12m30s ahead of".
func skewText(diff int64) string {
	d := (time.Duration(abs64(diff)) * time.Second).String()
	if diff > 0 {
		return d + " ahead of"
	}
	return d + " behind"
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

const ntpHint = "Tieroute servers must keep a synchronized clock: check that NTP (chrony, systemd-timesyncd, or ntpd) is running"

// writeClockSkew refuses a client request whose timestamp `ts` is more than `limit`
// seconds from this server's clock, saying so in words, with this server's time in `now`.
func (s *Server) writeClockSkew(w http.ResponseWriter, ts, limit int64) {
	n := now()
	diff := ts - n
	if s.clock.due("client") {
		s.log.Warn("clock: refused a client request dated "+skewText(diff)+" this server's clock",
			"limit", time.Duration(limit)*time.Second, "server_time", time.Unix(n, 0).UTC().Format(time.RFC3339),
			"hint", "if many clients are off by about the same amount, this server's clock is wrong. "+ntpHint)
	}
	writeBody(w, http.StatusBadRequest, wire.Error{
		Code: wire.ErrCodeClockSkew,
		Msg:  fmt.Sprintf("the request is dated %s this server's clock, more than the %s allowed: check the device's date and time", skewText(diff), time.Duration(limit)*time.Second),
		Now:  n,
	})
}

// writeS2SClockSkew refuses a peer's request dated too far from our clock (SPEC §8.3).
func (s *Server) writeS2SClockSkew(w http.ResponseWriter, e *fed.SkewError) {
	diff := e.TS - e.Now
	if s.clock.due("in|" + e.From) {
		s.log.Error("clock: refused a request claiming to be from "+e.From+": its clock is "+skewText(diff)+" ours (the sender isn't verified until the clocks agree)",
			"limit", time.Duration(fed.MaxSkew)*time.Second, "server_time", time.Unix(e.Now, 0).UTC().Format(time.RFC3339),
			"hint", "federation with it fails until the clocks agree. If several servers are off the same way, this server's clock is wrong. "+ntpHint)
	}
	writeBody(w, http.StatusUnauthorized, wire.Error{
		Code: wire.ErrCodeClockSkew,
		Msg:  fmt.Sprintf("the request is dated %s %s's clock, more than the %s allowed: %s", skewText(diff), s.cfg.Name, time.Duration(fed.MaxSkew)*time.Second, ntpHint),
		Now:  e.Now,
	})
}

// peerClock hears from federation how far a peer's clock is from ours: from the Date
// header of any answer more than a minute off, or from a peer refusing us for clock-skew.
func (s *Server) peerClock(peer string, offset int64, refused bool) {
	// The peer is `offset` seconds from us; we're the opposite from it.
	if refused {
		if s.clock.due("out|" + peer) {
			s.log.Error("clock: "+peer+" refused our request because our clocks are too far apart: ours is "+skewText(-offset)+" its",
				"hint", "federation with it fails until the clocks agree. If several servers say so, this server's clock is wrong. "+ntpHint)
		}
		return
	}
	if s.clock.due("drift|" + peer) {
		s.log.Warn("clock: "+peer+"'s clock is "+skewText(offset)+" ours",
			"limit", time.Duration(fed.MaxSkew)*time.Second,
			"hint", "servers further apart than the limit can't federate. If several servers are off the same way, this server's clock is wrong. "+ntpHint)
	}
}

// asSkew picks out an incoming S2S request refused for its clock.
func asSkew(err error) (*fed.SkewError, bool) {
	var e *fed.SkewError
	return e, errors.As(err, &e)
}
