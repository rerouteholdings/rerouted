package sfu

// Activity counts the rooms with anyone in them, and the devices in those rooms.
func (s *SFU) Activity() (rooms, participants int) {
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	rs := make([]*Room, 0, len(s.rooms))
	for _, r := range s.rooms {
		rs = append(rs, r)
	}
	s.mu.Unlock()
	for _, r := range rs {
		if n := r.Len(); n > 0 {
			rooms++
			participants += n
		}
	}
	return rooms, participants
}
