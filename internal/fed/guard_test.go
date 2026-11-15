package fed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
)

func TestPublicAddr(t *testing.T) {
	for _, c := range []struct {
		addr   string
		public bool
	}{
		{"93.184.215.14", true},
		{"2606:2800:21f:cb07:6820:80da:af6b:8b2c", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"0.1.2.3", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"100.100.100.100", false},
		{"169.254.169.254", false}, // cloud metadata
		{"fe80::1", false},
		{"fd00::1", false},
		{"192.0.0.170", false},
		{"198.18.0.1", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"255.255.255.255", false},
		{"240.0.0.1", false},
		{"::ffff:127.0.0.1", false},    // IPv4-mapped
		{"::ffff:93.184.215.14", true}, // IPv4-mapped
		{"64:ff9b::a9fe:a9fe", false},  // NAT64 for 169.254.169.254
		{"64:ff9b::5db8:d70e", true},   // NAT64 for 93.184.215.14
	} {
		if got := PublicAddr(netip.MustParseAddr(c.addr), nil); got != c.public {
			t.Errorf("%s: public %v, want %v", c.addr, got, c.public)
		}
	}
	allow := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")}
	for _, a := range []string{"10.9.8.7", "127.0.0.1", "::ffff:10.1.1.1"} {
		if !PublicAddr(netip.MustParseAddr(a), allow) {
			t.Errorf("%s is in REROUTED_FED_ALLOW but refused", a)
		}
	}
	if PublicAddr(netip.MustParseAddr("127.0.0.2"), allow) {
		t.Error("127.0.0.2 is outside REROUTED_FED_ALLOW but allowed")
	}
}

// Outside dev mode, a server name that leads to this host or its network is refused when
// the connection is made, unless REROUTED_FED_ALLOW permits it.
func TestPublicOnlyRefusesInternalAddresses(t *testing.T) {
	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer doc.Close()
	ctx := context.Background()
	f := New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
	f.PublicOnly(nil)
	if _, err := f.get(ctx, "a.test", "/x"); !errors.Is(err, ErrNotPublic) {
		t.Fatalf("GET to 127.0.0.1: %v, want ErrNotPublic", err)
	}
	f = New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
	f.PublicOnly([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")})
	if _, err := f.get(ctx, "a.test", "/x"); err != nil {
		t.Fatalf("GET to 127.0.0.1 with REROUTED_FED_ALLOW=127.0.0.0/8: %v", err)
	}
	// Without PublicOnly (dev mode), nothing changes.
	f = New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
	if _, err := f.get(ctx, "a.test", "/x"); err != nil {
		t.Fatalf("dev mode GET: %v", err)
	}
}

// A redirect can't leave https, and can't lead somewhere a direct request couldn't go.
func TestPublicOnlyRedirects(t *testing.T) {
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	ctx := context.Background()
	for _, c := range []struct{ to, want string }{
		{"http://127.0.0.1:1/x", "only https is followed"},
		{"https://169.254.169.254/latest/meta-data/", ErrNotPublic.Error()},
	} {
		doc := httptest.NewTLSServer(http.RedirectHandler(c.to, http.StatusFound))
		f := New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
		f.HTTP = doc.Client()
		f.PublicOnly(loopback)
		_, err := f.get(ctx, "a.test", "/x")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("redirect to %s: %v, want %q", c.to, err, c.want)
		}
		doc.Close()
	}
	// A redirect that stays on https, to an allowed address, is still followed.
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer final.Close()
	doc := httptest.NewUnstartedServer(http.RedirectHandler(final.URL+"/y", http.StatusFound))
	doc.TLS = final.TLS
	doc.StartTLS()
	defer doc.Close()
	f := New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
	f.HTTP = final.Client()
	f.PublicOnly(loopback)
	if _, err := f.get(ctx, "a.test", "/x"); err != nil {
		t.Fatalf("https redirect to an allowed address: %v", err)
	}
}
