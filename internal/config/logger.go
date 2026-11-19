package config

import (
	"io"
	"log/slog"
)

// Logger makes the server's logger, writing to w in REROUTED_LOG_FORMAT at
// REROUTED_LOG_LEVEL. A reload (Reload) changes its level; the format needs a restart.
func (c *Config) Logger(w io.Writer) *slog.Logger {
	c.Defaults()
	opts := &slog.HandlerOptions{Level: &c.live.level}
	if c.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
