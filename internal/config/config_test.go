package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestFedAllow(t *testing.T) {
	t.Setenv("REROUTED_NAME", "chat.test")
	t.Setenv("REROUTED_FED_ALLOW", " 10.0.0.0/8, 192.168.1.7 ,fd00::/8,10.1.2.3/16")
	c, err := Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.7/32"),
		netip.MustParsePrefix("fd00::/8"),
		netip.MustParsePrefix("10.1.0.0/16"),
	}
	if !slices.Equal(c.FedAllow, want) {
		t.Fatalf("FedAllow %v, want %v", c.FedAllow, want)
	}
	t.Setenv("REROUTED_FED_ALLOW", "intranet")
	if _, err := Load("/nonexistent"); err == nil || !strings.Contains(err.Error(), "REROUTED_FED_ALLOW") {
		t.Fatalf("a bad network: %v", err)
	}
}
