package metrics

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/api"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

func TestCollect(t *testing.T) {
	st, err := sqlite.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := serverkey.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Name: "chat.example", Handles: "chat.example", Registration: "invite", RegistrationCode: "a-registration-code"}
	server := api.New(cfg, key, slog.New(slog.DiscardHandler), st)
	var rq Requests
	h := rq.Wrap(server.Handler())
	for _, path := range []string{"/.well-known/tieroute/server", "/no/such/path", "/.well-known/tieroute/handle?h=kat.chat.example"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	ms := Collect(t.Context(), Sources{Server: server, Store: st, Requests: &rq, Started: time.Now(),
		RestartPending: func() bool { return true }, TurnAllocations: func() int { return 3 }})

	// No label can name an identity, a handle, a device, or a server: only these exist.
	allowed := map[string]bool{"version": true, "class": true}
	names := map[string]bool{}
	for _, m := range ms {
		names[m.Name] = true
		if !strings.HasPrefix(m.Name, "rerouted_") || (m.Type != "gauge" && m.Type != "counter") {
			t.Errorf("metric %s %s", m.Name, m.Type)
		}
		for _, s := range m.Samples {
			for _, l := range s.Labels {
				if !allowed[l[0]] {
					t.Errorf("%s has a label %q", m.Name, l[0])
				}
			}
		}
	}
	for _, want := range []string{"rerouted_identities", "rerouted_devices_signed_in", "rerouted_communities", "rerouted_outbox_requests",
		"rerouted_s2s_send_failures_total", "rerouted_streams", "rerouted_voice_rooms", "rerouted_voice_participants",
		"rerouted_http_responses_total", "rerouted_database_bytes", "rerouted_uptime_seconds", "rerouted_build_info", "rerouted_turn_allocations"} {
		if !names[want] {
			t.Errorf("no %s", want)
		}
	}

	rec := httptest.NewRecorder()
	Handler(func() []Metric { return ms }).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	text := string(body)
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatal(rec.Header())
	}
	for _, want := range []string{
		"# TYPE rerouted_http_responses_total counter\n",
		`rerouted_http_responses_total{class="2xx"} 1` + "\n",
		`rerouted_http_responses_total{class="4xx"} 2` + "\n",
		"rerouted_restart_pending 1\n",
		"rerouted_turn_allocations 3\n",
		"rerouted_identities 0\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	for _, leak := range []string{"chat.example", "kat"} {
		if strings.Contains(text, leak) {
			t.Errorf("the metrics mention %q", leak)
		}
	}
}

func TestWriteEscapes(t *testing.T) {
	var b strings.Builder
	Write(&b, []Metric{{Name: "x", Help: "a\nb\\c", Type: "gauge", Samples: []Sample{{Labels: [][2]string{{"l", "q\"\n"}}, Value: 1.5}}}})
	if want := "# HELP x a\\nb\\\\c\n# TYPE x gauge\nx{l=\"q\\\"\\n\"} 1.5\n"; b.String() != want {
		t.Fatalf("%q", b.String())
	}
}
