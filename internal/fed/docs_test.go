package fed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

func TestValidName(t *testing.T) {
	for _, n := range []string{"chat.example", "a.test", "kat.chat.example", "xn--bcher-kva.example", "Chat.Example", "localhost", "a-b.c1.example"} {
		if !ValidName(n) {
			t.Errorf("%q is a DNS name", n)
		}
	}
	for _, n := range []string{"", ".", "a..b", "chat.example.", "chat.example:8443", "chat.example/x", "chat.example/x?", "user@chat.example",
		"chat.example#f", "127.0.0.1", "10.1", "[::1]", "::1", "-a.example", "a-.example", "a b.example", "a_b.example", "é.example",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "b"} {
		if ValidName(n) {
			t.Errorf("%q isn't a DNS name", n)
		}
	}
}

// A sender or handle that isn't a DNS name is refused before anything is fetched: a name
// goes into a URL as it is, and "host:port/path?" would choose where the request goes.
func TestNamesNeverChooseURLs(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer ts.Close()
	evil := strings.TrimPrefix(ts.URL, "http://") + "/x?"
	f := New("b.test", serverkey.Key{}, nil)
	_, priv, _ := ed25519.GenerateKey(nil)
	sig, _ := wire.SignKID("s2s", s2sRequest{From: evil, To: "b.test", Path: "ping", TS: time.Now().Unix(), Nonce: make([]byte, 16), Body: wire.Raw(`{}`)}, priv, "k")
	enc, _ := sig.Encode()
	_, _, err := f.Verify(context.Background(), enc, "ping")
	if _, unavailable := errors.AsType[*UnavailableError](err); err == nil || unavailable {
		t.Fatalf("a sender named %q: %v, want a refusal", evil, err)
	}
	if _, err := f.ServerDoc(context.Background(), evil); err == nil {
		t.Fatal("a server document for a URL")
	}
	if _, err := f.ResolveHandle(context.Background(), evil); err == nil {
		t.Fatal("a handle that's a URL")
	}
	if _, _, err := f.Fetch(context.Background(), evil, "ping", []byte(`{}`)); err == nil {
		t.Fatal("a call to a URL")
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests were made", hits.Load())
	}
}

// A name costs one fetch at a time, a failure is remembered for a moment, and the cache
// keeps to its size.
func TestServerDocBounds(t *testing.T) {
	var hits atomic.Int32
	fail := atomic.Bool{}
	gate := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-gate
		if fail.Load() {
			http.Error(w, "down", 500)
			return
		}
		b, _ := wire.Marshal(map[string]any{"name": r.Host, "pad": strings.Repeat("x", 1000)})
		w.Write(b)
	}))
	defer ts.Close()
	peers := map[string]string{}
	for i := 0; i < 8; i++ {
		peers[fmt.Sprintf("s%d.test", i)] = ts.URL
	}
	f := New("b.test", serverkey.Key{}, peers)
	ctx := context.Background()

	// Twenty callers, one fetch.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.ServerDoc(ctx, "s0.test"); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d fetches for 20 callers", n)
	}

	// A failure is answered from memory until failTTL passes.
	fail.Store(true)
	hits.Store(0)
	for i := 0; i < 5; i++ {
		if _, err := f.ServerDoc(ctx, "s1.test"); err == nil {
			t.Fatal("a failed fetch succeeded")
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d fetches of a server that's down", n)
	}
	f.mu.Lock()
	f.failed["s1.test"] = failedDoc{err: errors.New("x"), until: time.Now().Add(-time.Second)}
	f.mu.Unlock()
	fail.Store(false)
	if _, err := f.ServerDoc(ctx, "s1.test"); err != nil {
		t.Fatalf("after the failure expired: %v", err)
	}

	// The cache keeps to its size: the documents fetched longest ago go.
	defer func(old int) { maxDocBytes = old }(maxDocBytes)
	maxDocBytes = 3500 // three of these documents
	for i := 2; i < 8; i++ {
		if _, err := f.ServerDoc(ctx, fmt.Sprintf("s%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	n, size := len(f.docs), f.docBytes
	_, newest := f.docs["s7.test"]
	_, oldest := f.docs["s0.test"]
	f.mu.Unlock()
	if n > 3 || size > maxDocBytes || !newest || oldest {
		t.Fatalf("%d documents, %d bytes cached; newest kept %v, oldest kept %v", n, size, newest, oldest)
	}
}

// Responses over 1 MiB are read a few at a time.
func TestBigResponses(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 3<<20)
	if b, err := readResponse(context.Background(), bytes.NewReader(big)); err != nil || len(b) != len(big) {
		t.Fatalf("a 3 MiB response: %d bytes, %v", len(b), err)
	}
	if b, err := readResponse(context.Background(), bytes.NewReader(big[:100])); err != nil || len(b) != 100 {
		t.Fatalf("a small response: %d bytes, %v", len(b), err)
	}
	for i := 0; i < bigResponses; i++ {
		bigResponse <- struct{}{}
	}
	defer func() {
		for i := 0; i < bigResponses; i++ {
			<-bigResponse
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := readResponse(ctx, bytes.NewReader(big)); err == nil {
		t.Fatal("a big response was read with every slot taken")
	}
	if b, err := readResponse(ctx, bytes.NewReader(big[:100])); err != nil || len(b) != 100 {
		t.Fatalf("a small response with every slot taken: %v", err)
	}
}
