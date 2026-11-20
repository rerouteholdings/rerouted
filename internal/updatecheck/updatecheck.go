// Package updatecheck asks rerouteholdings.llc whether a newer rerouted has been released,
// when the operator turns it on (REROUTED_UPDATE_CHECK=on). The request carries only the
// generic User-Agent, with rerouted's version, and nothing that names the server.
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// URL is where the latest release is described.
const URL = "https://rerouteholdings.llc/reroute/linux/rerouted/latest.json"

// Release is the latest release, as latest.json describes it.
type Release struct {
	Version   string `json:"version"`
	Published string `json:"published"`
	Notes     string `json:"notes"`
}

// Checker checks for a newer release.
type Checker struct {
	URL       string       // default URL
	Current   string       // this binary's version
	UserAgent string       // sent as User-Agent
	Client    *http.Client // default: a client with a 30 s timeout, through HTTPS_PROXY if set
	Log       *slog.Logger
	// Enabled is asked before each check, so a reload can turn checks on or off.
	Enabled func() bool
	// OnNewer hears about each newer version once.
	OnNewer func(Release)

	told string // the newest version reported so far
}

// Run checks after a random delay of two to five minutes, then once a day, until ctx ends.
func (c *Checker) Run(ctx context.Context) {
	delay := 2*time.Minute + rand.N(3*time.Minute)
	t := time.NewTimer(delay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if c.Enabled == nil || c.Enabled() {
			c.Check(ctx)
		}
		t.Reset(24 * time.Hour)
	}
}

// Check fetches the latest release once, and reports it if it's newer than Current and
// hasn't been reported yet. Failures log at debug level only.
func (c *Checker) Check(ctx context.Context) (Release, bool) {
	r, err := c.fetch(ctx)
	if err != nil {
		c.Log.Debug("update check failed", "err", err)
		return Release{}, false
	}
	if !Newer(r.Version, c.Current) || (c.told != "" && !Newer(r.Version, c.told)) {
		return r, false
	}
	c.told = r.Version
	c.Log.Info("a newer rerouted is available", "version", r.Version, "notes", r.Notes)
	if c.OnNewer != nil {
		c.OnNewer(r)
	}
	return r, true
}

func (c *Checker) fetch(ctx context.Context) (Release, error) {
	var r Release
	url := c.URL
	if url == "" {
		url = URL
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return r, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil {
		return r, err
	}
	if _, ok := parse(r.Version); !ok {
		return r, errors.New("latest.json has no valid version")
	}
	return r, nil
}

// semver is a parsed version: major, minor, patch, and prerelease identifiers.
type semver struct {
	n   [3]uint64
	pre []string
}

func parse(v string) (semver, bool) {
	var s semver
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, _, _ = strings.Cut(v, "+") // build metadata doesn't count
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return s, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return s, false
		}
		s.n[i] = n
	}
	if hasPre {
		if pre == "" {
			return s, false
		}
		s.pre = strings.Split(pre, ".")
	}
	return s, true
}

// Newer reports whether version a is newer than b, by semantic versioning: a prerelease
// sorts before its release. A version that doesn't parse is never newer.
func Newer(a, b string) bool {
	x, ok := parse(a)
	if !ok {
		return false
	}
	y, ok := parse(b)
	if !ok {
		return true // this build has no proper version: any release is newer
	}
	return compare(x, y) > 0
}

func compare(x, y semver) int {
	for i := range 3 {
		if x.n[i] != y.n[i] {
			if x.n[i] > y.n[i] {
				return 1
			}
			return -1
		}
	}
	switch {
	case len(x.pre) == 0 && len(y.pre) == 0:
		return 0
	case len(x.pre) == 0:
		return 1
	case len(y.pre) == 0:
		return -1
	}
	for i := 0; i < len(x.pre) && i < len(y.pre); i++ {
		a, b := x.pre[i], y.pre[i]
		an, aerr := strconv.ParseUint(a, 10, 64)
		bn, berr := strconv.ParseUint(b, 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an > bn {
					return 1
				}
				return -1
			}
		case aerr == nil: // numeric identifiers sort before alphanumeric ones
			return -1
		case berr == nil:
			return 1
		case a != b:
			if a > b {
				return 1
			}
			return -1
		}
	}
	switch {
	case len(x.pre) > len(y.pre):
		return 1
	case len(x.pre) < len(y.pre):
		return -1
	}
	return 0
}
