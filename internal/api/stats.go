package api

// Stats are the running server's aggregate counts, for metrics and the status file. They
// never name an identity.
type Stats struct {
	Streams           int   // open GET stream connections, on every wire version and community
	VoiceRooms        int   // community voice channels with anyone in them
	VoiceParticipants int   // devices in those channels
	SendFailures      int64 // S2S requests that failed or were refused since the start
}

// Stats counts what's going on now, across both wire versions and every community. Call it
// on the Server New returned.
func (s *Server) Stats() Stats {
	var st Stats
	for _, srv := range []*Server{s, s.v2} {
		if srv == nil {
			continue
		}
		st.Streams += srv.streams.count()
		st.SendFailures += srv.sendFailures.Load()
	}
	if s.comm != nil {
		for _, c := range s.comm.byName {
			st.Streams += c.streams.count()
			if c.srv != nil && c.srv != s.v2 {
				st.SendFailures += c.srv.sendFailures.Load()
			}
		}
		st.VoiceRooms, st.VoiceParticipants = s.comm.sfu.Activity()
	}
	return st
}

// count is how many streams are open.
func (ss *streams) count() int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	n := 0
	for _, m := range ss.m {
		n += len(m)
	}
	return n
}
