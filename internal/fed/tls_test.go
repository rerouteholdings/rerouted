package fed

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Outbound S2S connections offer the hybrid key exchange X25519MLKEM768 (SPEC §3): a
// server that takes nothing else still gets a connection. That's Go's default; nothing in
// rerouted's transport or build turns it off.
func TestOutboundOffersHybridTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.CurveID != tls.X25519MLKEM768 {
			t.Errorf("negotiated %s", r.TLS.CurveID)
		}
	}))
	srv.TLS = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	srv.StartTLS()
	defer srv.Close()
	tr := newTransport()
	tr.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatalf("a server that takes only X25519MLKEM768: %v", err)
	}
	resp.Body.Close()
}
