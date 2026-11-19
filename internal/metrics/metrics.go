// Package metrics serves rerouted's metrics in the Prometheus text format (version 0.0.4),
// written by hand so the server needs no client library. Every metric is an aggregate:
// labels never carry an identity, a handle, a device, or a server name.
package metrics

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// Metric is one metric family: a name, its help text, its type, and its samples.
type Metric struct {
	Name    string
	Help    string
	Type    string // "gauge" or "counter"
	Samples []Sample
}

// Sample is one value of a metric, with its labels as name and value pairs.
type Sample struct {
	Labels [][2]string
	Value  float64
}

// Gauge is a metric with one unlabeled sample.
func Gauge(name, help string, v float64) Metric {
	return Metric{Name: name, Help: help, Type: "gauge", Samples: []Sample{{Value: v}}}
}

// Counter is a counter with one unlabeled sample.
func Counter(name, help string, v float64) Metric {
	return Metric{Name: name, Help: help, Type: "counter", Samples: []Sample{{Value: v}}}
}

// Write writes ms in the Prometheus text format.
func Write(w io.Writer, ms []Metric) error {
	b := bufio.NewWriter(w)
	for _, m := range ms {
		b.WriteString("# HELP " + m.Name + " " + escapeHelp(m.Help) + "\n")
		b.WriteString("# TYPE " + m.Name + " " + m.Type + "\n")
		for _, s := range m.Samples {
			b.WriteString(m.Name)
			if len(s.Labels) > 0 {
				b.WriteByte('{')
				for i, l := range s.Labels {
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(l[0] + `="` + escapeLabel(l[1]) + `"`)
				}
				b.WriteByte('}')
			}
			b.WriteString(" " + strconv.FormatFloat(s.Value, 'g', -1, 64) + "\n")
		}
	}
	return b.Flush()
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

// Handler serves GET /metrics with what gather returns at each request.
func Handler(gather func() []Metric) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		Write(w, gather())
	})
	return mux
}

// Requests counts HTTP responses by status class (1xx to 5xx).
type Requests struct {
	class [6]atomic.Int64
}

// Wrap counts next's responses.
func (rq *Requests) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			code := sw.code
			if code == 0 {
				code = http.StatusOK
			}
			if sw.hijacked {
				code = http.StatusSwitchingProtocols
			}
			if c := code / 100; c >= 1 && c <= 5 {
				rq.class[c].Add(1)
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

// Metric is the counts so far, as rerouted_http_responses_total.
func (rq *Requests) Metric() Metric {
	m := Metric{Name: "rerouted_http_responses_total", Help: "HTTP responses sent, by status class.", Type: "counter"}
	for c := 1; c <= 5; c++ {
		m.Samples = append(m.Samples, Sample{Labels: [][2]string{{"class", strconv.Itoa(c) + "xx"}}, Value: float64(rq.class[c].Load())})
	}
	return m
}

// statusWriter records the status code a handler sends. It passes through flushing and
// hijacking, which streams and WebSockets need.
type statusWriter struct {
	http.ResponseWriter
	code     int
	hijacked bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	c, rw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return c, rw, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
