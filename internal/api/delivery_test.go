package api

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

// inboxCount counts what's in u's inbox, without acking it.
func inboxCount(u *testUser) int {
	u.t.Helper()
	var res struct {
		Items []inboxItem `json:"items"`
	}
	if c := call(u.t, u.ts, "GET", "inbox", u.token, nil, &res); c != 200 {
		u.t.Fatalf("inbox: %d", c)
	}
	return len(res.Items)
}

// A delivery that can't be stored is reported as unavailable, not as sent, and leaves
// nothing behind, so the client's retry delivers it. Its result is kept in storage, so a
// resubmitted ID gets it back, even from a restarted server, and isn't delivered twice.
func TestSendFailureCanBeRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	kat := newUser(t, testServerWith(t, st), "kat")
	id := randBytes(16)

	if _, err := db.Exec("CREATE TRIGGER fail_inbox BEFORE INSERT ON inbox BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	if c, res := sendLink(kat, id); c != 200 || res.Status != "rejected" || res.Error != "unavailable" {
		t.Fatalf("send with storage failing: %d %+v, want rejected unavailable", c, res)
	}
	if _, err := db.Exec("DROP TRIGGER fail_inbox"); err != nil {
		t.Fatal(err)
	}
	if n := inboxCount(kat); n != 0 {
		t.Fatalf("a failed delivery left %d items", n)
	}
	for range 2 {
		if c, res := sendLink(kat, id); c != 200 || res.Status != "sent" {
			t.Fatalf("retry: %d %+v", c, res)
		}
	}
	if n := inboxCount(kat); n != 1 {
		t.Fatalf("after a retry and a resubmit: %d items, want 1", n)
	}

	// A restart: a new server on the same storage.
	kat.ts = testServerWith(t, st)
	if c, res := sendLink(kat, id); c != 200 || res.Status != "sent" {
		t.Fatalf("resubmit after a restart: %d %+v", c, res)
	}
	if n := inboxCount(kat); n != 1 {
		t.Fatalf("after a restart: %d items, want 1", n)
	}
}

// The same ID sent many times at once is delivered once, and every request gets the
// result.
func TestConcurrentResubmitsDeliverOnce(t *testing.T) {
	kat := newUser(t, testServer(t), "kat")
	id := randBytes(16)
	var wg sync.WaitGroup
	errs := make(chan string, 20)
	for range 20 {
		wg.Go(func() {
			if c, res := sendLink(kat, id); c != 200 || res.Status != "sent" {
				errs <- fmt.Sprintf("%d %+v", c, res)
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error("a concurrent resubmit:", e)
	}
	if n := inboxCount(kat); n != 1 {
		t.Fatalf("%d items, want 1", n)
	}
}
