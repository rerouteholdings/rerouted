//go:build rerouted_testclock

package api

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// A movable clock for demo/a04.sh, which needs the homeserver's clock (SPEC §8.4) to read
// minutes or an hour past a commit's hub receipt without waiting for it. It exists only in
// binaries built with -tags rerouted_testclock (release builds don't contain it; see
// testclock_off.go), and even then only with REROUTED_DEV=on and REROUTED_TEST_CLOCK_FILE
// naming a file that holds a whole number of seconds to add to this server's time. The file
// is read on every reading of the clock, so a test can move it while servers run. Several
// servers given the same file move together, so federation (which signs and checks S2S
// requests on the real clock) keeps working.
var testClock struct {
	once sync.Once
	path string
}

func testClockOffset() int64 {
	testClock.once.Do(func() {
		p := os.Getenv("REROUTED_TEST_CLOCK_FILE")
		if p == "" {
			return
		}
		if os.Getenv("REROUTED_DEV") != "on" {
			fmt.Fprintln(os.Stderr, "rerouted: REROUTED_TEST_CLOCK_FILE ignored: the test clock needs REROUTED_DEV=on")
			return
		}
		testClock.path = p
		fmt.Fprintln(os.Stderr, "rerouted: TEST CLOCK: this server's protocol time is shifted by the seconds in", p)
	})
	if testClock.path == "" {
		return 0
	}
	b, err := os.ReadFile(testClock.path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
