package turnrelay

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

const secret = "a-secret-of-at-least-16"

// Credentials as GET turn makes them (internal/api/turn.go) pass; others don't.
func TestCheckUser(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	user := fmt.Sprintf("%d:%s", now.Unix()+3600, "tr:someone")
	pass := Credential(secret, user)
	u, key, ok := checkUser(user, "chat.example", secret, now)
	if !ok || u != "tr:someone" {
		t.Fatal("good credentials refused")
	}
	if want := turn.GenerateAuthKey(user, "chat.example", pass); string(key) != string(want) {
		t.Fatal("key doesn't match the password GET turn hands out")
	}
	if _, key, _ := checkUser(user, "chat.example", "another-secret-entirely", now); string(key) == string(turn.GenerateAuthKey(user, "chat.example", pass)) {
		t.Fatal("another secret gives the same key")
	}
	for _, bad := range []string{
		fmt.Sprintf("%d:tr:someone", now.Unix()-1), // expired
		"tr:someone",                         // no expiry
		strconv.FormatInt(now.Unix()+60, 10), // no user
		"soon:tr:someone",
	} {
		if _, _, ok := checkUser(bad, "chat.example", secret, now); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, _, ok := checkUser(user, "chat.example", "", now); ok {
		t.Error("accepted with no secret")
	}
}

func TestAllowed(t *testing.T) {
	for _, ip := range []string{"10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "ff02::1", "64:ff9b::a00:1"} {
		if Allowed(net.ParseIP(ip), false) {
			t.Errorf("%s allowed", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "93.184.216.34", "2606:4700::1111", "::ffff:1.1.1.1"} {
		if !Allowed(net.ParseIP(ip), false) {
			t.Errorf("%s refused", ip)
		}
	}
	pub := net.ParseIP("8.8.4.4")
	cfg := Config{PublicIP: pub, MinPort: 49160, MaxPort: 49200}
	if permitted(&net.UDPAddr{IP: pub, Port: 22}, cfg) || !permitted(&net.UDPAddr{IP: pub, Port: 49170}, cfg) {
		t.Fatal("this host's own address: only the relay ports")
	}
}

// A client with GET turn's credentials gets an allocation, relays to a public peer, and
// can't reach private addresses.
func TestRelay(t *testing.T) {
	r, err := Start(Config{Listen: "127.0.0.1:0", PublicIP: net.ParseIP("127.0.0.1"), MinPort: 41000, MaxPort: 41100,
		Realm: "chat.example", Secret: func() string { return secret }, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	addr := r.Addr().String()

	dial := func(user, pass string) (*turn.Client, net.PacketConn) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: addr, TURNServerAddr: addr, Conn: conn, Username: user, Password: pass, Realm: "chat.example", RTO: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Listen(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(); conn.Close() })
		return c, conn
	}
	user := fmt.Sprintf("%d:tr:someone", time.Now().Unix()+3600)
	bad, _ := dial(user, Credential("not-the-secret-at-all", user))
	if _, err := bad.Allocate(); err == nil {
		t.Fatal("allocated with the wrong secret")
	}
	c, _ := dial(user, Credential(secret, user))
	relay, err := c.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if p := relay.LocalAddr().(*net.UDPAddr).Port; p < 41000 || p > 41100 {
		t.Fatalf("relay port %d outside the range", p)
	}
	if r.Allocations() != 1 {
		t.Fatalf("%d allocations", r.Allocations())
	}
	peer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer peer.Close()
	if _, err := relay.WriteTo([]byte("hello"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := peer.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("peer got %q, %v", buf[:n], err)
	}
	if err := c.CreatePermission(&net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5000}); err == nil {
		t.Fatal("permission to a private address granted")
	}
}
