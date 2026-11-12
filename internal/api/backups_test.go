package api

import (
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// SPEC §7.5: segments in order, retries harmless, snapshots compact, and the quota holds.
func TestBackups(t *testing.T) {
	ts := testServerCfg(t, newStore(t), func(c *config.Config) { c.BackupQuota = 1000 })
	kat := newUser(t, ts, "kat")
	put := func(seq int, ct []byte, snapshot bool) int {
		body := map[string]any{"seq": seq, "ct": ct}
		if snapshot {
			body["snapshot"] = true
		}
		return call(t, ts, "POST", "backup/put", kat.token, body, nil)
	}
	s0, s1 := randBytes(300), randBytes(300)
	if c := put(0, s0, true); c != 204 {
		t.Fatalf("segment 0: %d", c)
	}
	if c := put(1, s1, false); c != 204 {
		t.Fatalf("segment 1: %d", c)
	}
	if c := put(1, s1, false); c != 204 {
		t.Fatalf("a retry of segment 1: %d, want 204", c)
	}
	if c := put(1, randBytes(300), false); c != 409 {
		t.Fatalf("other bytes for segment 1: %d, want 409", c)
	}
	if c := put(0, randBytes(300), false); c != 409 {
		t.Fatalf("an older seq: %d, want 409", c)
	}
	if c := put(2, randBytes(500), false); c != 413 {
		t.Fatalf("over the 1000-byte quota: %d, want 413", c)
	}
	if c := put(2, randBytes(500), true); c != 204 {
		t.Fatalf("a snapshot that fits once it replaces the rest: %d", c)
	}
	var list struct {
		Segments []struct {
			Seq      int64 `json:"seq"`
			Size     int64 `json:"size"`
			Snapshot bool  `json:"snapshot"`
		} `json:"segments"`
	}
	call(t, ts, "GET", "backup/list", kat.token, nil, &list)
	if len(list.Segments) != 1 || list.Segments[0].Seq != 2 || !list.Segments[0].Snapshot || list.Segments[0].Size != 500 {
		t.Fatalf("after the snapshot: %+v", list.Segments)
	}
	var got struct {
		CT wire.Bytes `json:"ct"`
	}
	if c := call(t, ts, "GET", "backup/get?seq=2", kat.token, nil, &got); c != 200 || len(got.CT) != 500 {
		t.Fatalf("get: %d", c)
	}
	if c := call(t, ts, "GET", "backup/get?seq=0", kat.token, nil, nil); c != 404 {
		t.Fatalf("a compacted segment: %d, want 404", c)
	}
	// A full 1 MiB segment fits in a backup/put body, though it's over the 1 MiB JSON limit.
	ts2 := testServer(t)
	kat2 := newUser(t, ts2, "kat")
	if c := call(t, ts2, "POST", "backup/put", kat2.token, map[string]any{"seq": 0, "ct": randBytes(1<<20 + 28)}, nil); c != 204 {
		t.Fatalf("a full-size segment: %d", c)
	}
}
