package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

func TestCheckupDevServer(t *testing.T) {
	clearRerouted(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/tieroute/server" || r.Host != "chat.test" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"name":"chat.test","apis":[{"v":2}],"keys":[{"kid":"a","pub":"b"}]}`))
	}))
	defer srv.Close()
	turn := stunServer(t)
	dir := t.TempDir()
	env := writeEnv(t, dir)
	envText := "REROUTED_NAME=chat.test\nREROUTED_HANDLES=chat.test\nREROUTED_DEV=on\nREROUTED_PUBLIC_URL=http://chat.test\n" +
		"REROUTED_LISTEN=" + strings.TrimPrefix(srv.URL, "http://") + "\nREROUTED_DATA_DIR=" + dir + "/data\n" +
		"REROUTED_TURN_URLS=turn:" + turn + "?transport=udp\nREROUTED_TURN_SECRET=0123456789abcdef\n" +
		"REROUTED_DEV_PEERS=peer.test=" + srv.URL + "\n"
	writeFile(t, env, envText)
	var out bytes.Buffer
	c := &checkup{out: &out, timeout: 2 * time.Second, now: time.Now}
	c.run(env, "", "")
	s := out.String()
	for _, want := range []string{"PASS  listener", "INFO  https", "PASS  turn"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if c.fails != 0 {
		t.Fatalf("failures:\n%s", s)
	}
}

func TestCheckupNothingListening(t *testing.T) {
	clearRerouted(t)
	dir := t.TempDir()
	env := writeEnv(t, dir, "REROUTED_DEV=on", "REROUTED_PUBLIC_URL=http://chat.example")
	var out bytes.Buffer
	c := &checkup{out: &out, timeout: time.Second, now: time.Now}
	c.run(env, "", "")
	if c.fails == 0 || !strings.Contains(out.String(), "FAIL  listener") {
		t.Fatalf("%s", out.String())
	}
}

// stunServer answers STUN binding requests on a local UDP port, as a TURN server does.
func stunServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if req.Decode() != nil {
				continue
			}
			res := stun.MustBuild(stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess)
			pc.WriteTo(res.Raw, addr)
		}
	}()
	return pc.LocalAddr().String()
}
