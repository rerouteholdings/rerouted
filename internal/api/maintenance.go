package api

import (
	"context"
	"path/filepath"
	"time"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
)

// Retention (SPEC §10.4, §11.6, §14): inbox items, hub commits, and files are kept 30 days.
const retention = 30 * 24 * 3600

// RunMaintenance deletes what's past retention and saves the rate limits, once at start and
// then every 10 minutes, until ctx ends. Inboxes are also pruned whenever a device acks.
func (s *Server) RunMaintenance(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		s.maintain(ctx)
		select {
		case <-ctx.Done():
			s.saveLimits()
			return
		case <-t.C:
		}
	}
}

// limitsPath is where the rate limits are kept between restarts, or "" for none.
func (s *Server) limitsPath() string {
	if s.cfg.DataDir == "" || s.cfg.Store == "temp" {
		return ""
	}
	return filepath.Join(s.cfg.DataDir, "limits.json")
}

func (s *Server) saveLimits() {
	if p := s.limitsPath(); p != "" {
		if err := s.limits.save(p); err != nil {
			s.log.Error("saving rate limits", "err", err)
		}
	}
}

func (s *Server) maintain(ctx context.Context) {
	s.rotateKeys()
	before := now() - retention
	if err := s.st.Hub().PruneCommits(ctx, before); err != nil {
		s.log.Error("pruning hub commits", "err", err)
	}
	if n, err := s.st.Media().Expire(ctx, before); err != nil {
		s.log.Error("expiring files", "err", err)
	} else if n > 0 {
		s.log.Info("expired files", "n", n)
	}
	// Move reservations go once their handle hold ends. Registration never needs one.
	if n, err := s.st.Chains().PruneReservations(ctx, now()); err != nil {
		s.log.Error("pruning move reservations", "err", err)
	} else if n > 0 {
		s.log.Info("pruned move reservations", "n", n)
	}
	// Names whose 30-day hold ended are freed, but those the operator keeps (SPEC §5.3).
	if n, err := s.st.Chains().PruneHandles(ctx, now()); err != nil {
		s.log.Error("freeing held handles", "err", err)
	} else if n > 0 {
		s.log.Info("freed handles whose hold ended", "n", n)
	}
	// Delivery IDs and send results are kept as long as inbox items: far longer than any
	// retry, since the outbox gives up after 72 hours.
	if _, err := s.st.Inbox().PruneSeen(ctx, before); err != nil {
		s.log.Error("pruning seen delivery IDs", "err", err)
	}
	if _, err := s.st.Sent().Prune(ctx, before); err != nil {
		s.log.Error("pruning send results", "err", err)
	}
	if _, err := s.st.Sessions().PruneNonces(ctx, now()); err != nil {
		s.log.Error("pruning nonces", "err", err)
	}
	s.maintainCommunities(ctx)
	s.limits.sweep(now())
	s.saveLimits()
}

// rotateKeys moves each server key along as it ages (serverkey.Slot.Maintain): a successor
// is published 300 days in, and signs a week later, while the key it replaced stays
// published until its exp. Each community server name's own key rotates the same way.
func (s *Server) rotateKeys() {
	t := time.Unix(now(), 0)
	slots := map[string]*serverkey.Slot{"version 1": s.keys.V1, "version 2": s.keys.V2}
	if s.comm != nil {
		for _, c := range s.comm.byName {
			if c.keys != s.keys.V2 {
				slots["community "+c.name] = c.keys
			}
		}
	}
	for name, slot := range slots {
		before := slot.Published(t)
		if err := slot.Maintain(t); err != nil {
			s.log.Error("rotating a server key", "key", name, "err", err)
			continue
		}
		if after := slot.Published(t); !sameKIDs(before, after) {
			s.log.Info("server keys changed", "key", name, "signing", after[0].KID, "published", len(after))
		}
	}
}

func sameKIDs(a, b []serverkey.Published) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].KID != b[i].KID {
			return false
		}
	}
	return true
}
