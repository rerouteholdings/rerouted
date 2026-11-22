package fed

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// listen counts connections to a loopback port: something inside the server's network
// that federation must never be made to reach.
func listen(t *testing.T) (addr string, hits *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	hits = new(atomic.Int32)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	return l.Addr().String(), hits
}

// An S2S request naming an IP address and port as its sender, with a signature by no
// key anyone publishes, makes no outbound connection: server names are DNS names (SPEC
// §5.1), and nothing is fetched for one that isn't.
func TestVerifyDoesNotFetchForBadSenderName(t *testing.T) {
	addr, hits := listen(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	f := New("b.example", nil, nil)
	for _, from := range []string{addr, "127.0.0.1", "localhost", "[::1]:443", "a.example:8080", "a.example/x?", "A.example"} {
		sig, _ := wire.SignKID("s2s", s2sRequest{From: from, To: "b.example", Path: "ping", TS: time.Now().Unix(), Nonce: make([]byte, 16), Body: wire.Raw(`{}`)}, priv, "k1")
		enc, _ := sig.Encode()
		_, _, err := f.Verify(context.Background(), enc, "ping")
		if err == nil {
			t.Fatalf("from %q verified", from)
		}
		if _, ok := err.(*UnavailableError); ok {
			t.Errorf("from %q: %v, want a refusal, not a retry", from, err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("an unauthenticated request made %d connections to %s", n, addr)
	}
}

// Federation fetches don't follow redirects: a server document answered with a 302 to an
// internal address doesn't reach it.
func TestRedirectsNotFollowed(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect followed to %s", r.URL)
	}))
	defer internal.Close()
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/secret", http.StatusFound)
	}))
	defer peer.Close()
	f := New("b.test", nil, map[string]string{"a.test": peer.URL})
	f.HTTP.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: peer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	if _, err := f.ServerDoc(context.Background(), "a.test"); err == nil {
		t.Fatal("a redirected document was accepted")
	}
}

// API bases from a server's document must name a host by DNS name, not an IP address.
func TestAPIBaseMustNotBeIPLiteral(t *testing.T) {
	doc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"a.example","apis":[{"v":1,"s2s":"https://127.0.0.1:9/s2s/"},{"v":2,"s2s":"https://10.0.0.1/s2s/","community":"https://[::1]/c/"}],"keys":[]}`))
	}))
	defer doc.Close()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, doc.Listener.Addr().String())
	}
	f := New("b.example", nil, nil)
	f.HTTP = &http.Client{Transport: tr}
	if _, err := f.ServerDoc(context.Background(), "a.example"); err != nil {
		t.Fatal(err)
	}
	if b, err := f.S2SBase(context.Background(), "a.example"); err == nil {
		t.Errorf("v1 s2s base %q accepted", b)
	}
	f.V = wire.V2
	if b, err := f.S2SBase(context.Background(), "a.example"); err == nil {
		t.Errorf("v2 s2s base %q accepted", b)
	}
	if b, err := f.CommunityBase(context.Background(), "a.example"); err == nil {
		t.Errorf("community base %q accepted", b)
	}
}

// The federation transport refuses to connect to loopback, private, and link-local
// addresses, however a name resolved to them.
func TestTransportRefusesInternalAddresses(t *testing.T) {
	addr, hits := listen(t)
	resp, err := (&http.Client{Transport: newTransport(), Timeout: 5 * time.Second}).Get("http://" + addr + "/")
	if err == nil {
		resp.Body.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the transport connected to %s (%d times)", addr, n)
	}
}

func TestPublicAddr(t *testing.T) {
	for s, want := range map[string]bool{
		"1.1.1.1": true, "23.131.76.23": true, "2606:4700:4700::1111": true,
		"64:ff9b::101:101": true, // NAT64 of 1.1.1.1
		"127.0.0.1":        false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "0.1.2.3": false,
		"255.255.255.255": false, "224.0.0.1": false, "198.18.0.1": false, "240.0.0.1": false,
		"::": false, "::1": false, "fe80::1": false, "fd00::1": false, "fec0::1": false,
		"::ffff:127.0.0.1": false, "::ffff:169.254.169.254": false,
		"64:ff9b::a00:1": false, // NAT64 of 10.0.0.1
		"2002:7f00:1::":  false, // 6to4 of 127.0.0.1
		"2001::1":        false, // Teredo
		"ff02::1":        false,
	} {
		if got := publicAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("publicAddr(%s) = %v", s, got)
		}
	}
}
