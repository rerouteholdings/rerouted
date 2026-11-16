package egress

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/rerouteholdings/rerouted/internal/ipc"
)

func serve(t *testing.T, s *Server) Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "eg") // a unix socket's path is limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if s.Log == nil {
		s.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	go s.Serve(l)
	return Client{Path: sock}
}

func get(c Client, url string) (string, error) {
	hc := &http.Client{Transport: &http.Transport{DialContext: c.DialContext}}
	resp, err := hc.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// Only public addresses, REROUTED_FED_ALLOW's networks, and REROUTED_TLS_ASK_ALSO's exact
// hosts and ports; the bytes go both ways once connected.
func TestPolicy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello " + r.URL.Path)) }))
	defer ts.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer other.Close()

	c := serve(t, &Server{UID: -1})
	if _, err := get(c, ts.URL+"/x"); err == nil || !strings.Contains(err.Error(), "isn't a public address") {
		t.Fatalf("loopback with no policy: %v", err)
	}
	if _, err := c.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("cloud metadata")
	}

	c = serve(t, &Server{UID: -1, Policy: Policy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}})
	if body, err := get(c, ts.URL+"/x"); err != nil || body != "hello /x" {
		t.Fatalf("REROUTED_FED_ALLOW=127.0.0.0/8: %q %v", body, err)
	}

	c = serve(t, &Server{UID: -1, Policy: Policy{Local: LocalFrom([]string{ts.URL})}})
	if body, err := get(c, ts.URL+"/y"); err != nil || body != "hello /y" {
		t.Fatalf("a REROUTED_TLS_ASK_ALSO instance: %q %v", body, err)
	}
	if _, err := get(c, other.URL); err == nil {
		t.Fatal("another port on the same host")
	}
	if _, err := c.DialContext(context.Background(), "udp", "1.1.1.1:53"); err == nil {
		t.Fatal("UDP")
	}
}

func TestLocalFrom(t *testing.T) {
	m := LocalFrom([]string{"http://127.0.0.1:18091", "https://b.local", "http://[::1]:9", "::bad"})
	var got []string
	for k := range m {
		got = append(got, k)
	}
	slices.Sort(got)
	if want := []string{"127.0.0.1:18091", "[::1]:9", "b.local:443"}; !slices.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

// fakeDNS answers TXT queries over DNS's TCP framing, which Go's resolver uses on a
// connection that isn't a packet one.
func fakeDNS(records map[string][]string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			for {
				var n [2]byte
				if _, err := io.ReadFull(b, n[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(n[:]))
				if _, err := io.ReadFull(b, q); err != nil {
					return
				}
				var p dnsmessage.Parser
				h, err := p.Start(q)
				if err != nil {
					return
				}
				qs, _ := p.AllQuestions()
				bld := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: dnsmessage.RCodeSuccess})
				bld.StartQuestions()
				for _, qq := range qs {
					bld.Question(qq)
				}
				bld.StartAnswers()
				for _, qq := range qs {
					if qq.Type != dnsmessage.TypeTXT {
						continue
					}
					for _, txt := range records[qq.Name.String()] {
						bld.TXTResource(dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.TXTResource{TXT: []string{txt}})
					}
				}
				out, _ := bld.Finish()
				b.Write(binary.BigEndian.AppendUint16(nil, uint16(len(out))))
				b.Write(out)
			}
		}()
		return a, nil
	}}
}

func TestLookupTXT(t *testing.T) {
	c := serve(t, &Server{UID: -1, Resolver: fakeDNS(map[string][]string{"_tieroute.kat.example.": {"id=tr:abc", "v=1"}, "secret-data.evil.example.": {"x"}})})
	txt, err := c.LookupTXT(context.Background(), "_tieroute.kat.example")
	if err != nil || !slices.Equal(txt, []string{"id=tr:abc", "v=1"}) {
		t.Fatalf("TXT: %v %v", txt, err)
	}
	// Only handle records: any other name would carry data out in the query itself.
	for _, name := range []string{"secret-data.evil.example", "_tieroute.", "_tieroute.a/b", "kat.example"} {
		if _, err := c.LookupTXT(context.Background(), name); err == nil {
			t.Errorf("looked up %q", name)
		}
	}
}

func TestBadRequests(t *testing.T) {
	c := serve(t, &Server{UID: -1})
	for _, r := range []request{{Op: "connect", Host: "", Port: 443}, {Op: "connect", Host: "example.com", Port: 70000},
		{Op: "connect", Host: "example.com/x", Port: 443}, {Op: "connect", Host: "a b", Port: 443}, {Op: "nope"}} {
		if _, _, err := c.ask(context.Background(), r); err == nil {
			t.Errorf("%+v was accepted", r)
		}
	}
	if _, err := c.DialContext(context.Background(), "tcp", "no-port"); err == nil {
		t.Error("an address without a port")
	}
}

func TestPeerUID(t *testing.T) {
	if !ipc.PeerCheckSupported {
		t.Skip("no SO_PEERCRED here")
	}
	c := serve(t, &Server{UID: os.Getuid() + 1, Resolver: fakeDNS(nil)})
	if _, err := c.LookupTXT(context.Background(), "_tieroute.x.example"); err == nil {
		t.Fatal("another user's connection was served")
	}
	c = serve(t, &Server{UID: os.Getuid(), Resolver: fakeDNS(map[string][]string{"_tieroute.x.example.": {"ok"}})})
	if txt, err := c.LookupTXT(context.Background(), "_tieroute.x.example"); err != nil || len(txt) != 1 {
		t.Fatalf("the allowed user: %v %v", txt, err)
	}
}
