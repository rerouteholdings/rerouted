package api

import (
	"context"
	"path/filepath"
	"time"
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
	if s.cfg.DataDir == "" || s.cfg.Store == "mem" {
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
	s.limits.sweep(now())
	s.saveLimits()
}
