//go:build !rerouted_testclock

package api

// testClockOffset is always 0 outside test-clock builds: release builds read the real
// clock only (see testclock.go).
func testClockOffset() int64 { return 0 }
