package metrics

import (
	"context"
	"time"

	"github.com/rerouteholdings/rerouted/internal/api"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/version"
)

// Sources are what rerouted's metrics are read from.
type Sources struct {
	Server          *api.Server // the Server api.New returned
	Store           *sqlite.Store
	Requests        *Requests
	Started         time.Time
	RestartPending  func() bool
	UpdateAvailable func() bool
	TurnAllocations func() int // nil when the built-in relay is off
}

// Collect reads rerouted's metrics: aggregate counts only. The only labels are the build's
// version and an HTTP status class.
func Collect(ctx context.Context, src Sources) []Metric {
	b2f := func(f func() bool) float64 {
		if f != nil && f() {
			return 1
		}
		return 0
	}
	stats := src.Server.Stats()
	ms := []Metric{
		{Name: "rerouted_build_info", Help: "The running rerouted's version.", Type: "gauge",
			Samples: []Sample{{Labels: [][2]string{{"version", version.Number}}, Value: 1}}},
		Gauge("rerouted_uptime_seconds", "Seconds since rerouted started.", time.Since(src.Started).Seconds()),
		Gauge("rerouted_streams", "Open GET stream connections (WebSockets), on every wire version and community.", float64(stats.Streams)),
		Gauge("rerouted_voice_rooms", "Community voice channels with anyone in them.", float64(stats.VoiceRooms)),
		Gauge("rerouted_voice_participants", "Devices in community voice channels.", float64(stats.VoiceParticipants)),
		Counter("rerouted_s2s_send_failures_total", "S2S requests that failed or were refused, since the start.", float64(stats.SendFailures)),
		Counter("rerouted_push_sent_total", "Push notifications Apple's push service accepted, since the start.", float64(stats.PushesSent)),
		Counter("rerouted_push_failed_total", "Push notifications that failed, were refused, or were dropped, since the start.", float64(stats.PushesFailed)),
	}
	if src.Requests != nil {
		ms = append(ms, src.Requests.Metric())
	}
	ms = append(ms,
		Gauge("rerouted_restart_pending", "1 while a restart waits for voice calls to end.", b2f(src.RestartPending)),
		Gauge("rerouted_update_available", "1 once the update check has found a newer release.", b2f(src.UpdateAvailable)),
	)
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if db, err := src.Store.Stats(qctx); err == nil {
		ms = append(ms,
			Gauge("rerouted_identities", "Identities with a handle in use on this homeserver.", float64(db.Identities)),
			Gauge("rerouted_devices_signed_in", "Devices with a session that hasn't expired.", float64(db.Devices)),
			Gauge("rerouted_communities", "Communities on this server's community names.", float64(db.Communities)),
			Gauge("rerouted_outbox_requests", "S2S requests waiting to be sent.", float64(db.Outbox)),
			Gauge("rerouted_database_bytes", "The database's size in bytes, without its write-ahead log.", float64(db.Bytes)),
		)
	}
	if src.TurnAllocations != nil {
		ms = append(ms, Gauge("rerouted_turn_allocations", "Open allocations on the built-in call relay.", float64(src.TurnAllocations())))
	}
	return ms
}
