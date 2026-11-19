package sqlite

import (
	"context"
	"time"
)

// Stats are aggregate counts over the whole database, for metrics and the status file.
type Stats struct {
	Identities  int64 // identities with a handle in use here
	Devices     int64 // devices with a session that hasn't expired
	Communities int64 // communities created on this server's community names
	Outbox      int64 // S2S requests waiting to be sent
	Bytes       int64 // the database's size, without its write-ahead log
}

// Stats counts the database's contents. It reads through the read-only connections.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	var pages, size int64
	for _, q := range []struct {
		sql  string
		args []any
		into *int64
	}{
		{"SELECT COUNT(DISTINCT id) FROM handles WHERE hold = 0", nil, &st.Identities},
		{"SELECT COUNT(*) FROM (SELECT DISTINCT id, device FROM tokens WHERE expires >= ?)", []any{time.Now().Unix()}, &st.Devices},
		{"SELECT COUNT(*) FROM cm_communities", nil, &st.Communities},
		{"SELECT COUNT(*) FROM outbox", nil, &st.Outbox},
		{"PRAGMA page_count", nil, &pages},
		{"PRAGMA page_size", nil, &size},
	} {
		if err := s.rdb.QueryRowContext(ctx, q.sql, q.args...).Scan(q.into); err != nil {
			return st, err
		}
	}
	st.Bytes = pages * size
	return st, nil
}
