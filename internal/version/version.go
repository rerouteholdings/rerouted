// Package version is rerouted's own version, and the User-Agent it sends other servers.
package version

// Number is rerouted's version. A release build can set it:
//
//	go build -ldflags "-X github.com/rerouteholdings/rerouted/internal/version.Number=0.2.0" ./cmd/rerouted
var Number = "0.2.0-rc.2"

// UserAgent names rerouted on requests to other servers, so their logs can tell federation
// traffic from clients': for example "rerouted/0.1.0 (Tieroute homeserver; https://rerouteholdings.llc)".
func UserAgent() string {
	return "rerouted/" + Number + " (Tieroute homeserver; https://rerouteholdings.llc)"
}
