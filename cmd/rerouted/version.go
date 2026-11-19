package main

import (
	"fmt"
	"runtime"

	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/version"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// wireVersions are the Tieroute wire versions this rerouted speaks (SPEC §6.8).
var wireVersions = []int{wire.V1, wire.V2}

func runVersion(_ *globals, args []string) int {
	if len(args) > 1 {
		fmt.Println("version takes no arguments")
		return 2
	}
	fmt.Printf("rerouted %s\n", version.Number)
	fmt.Printf("go:       %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("schema:   %d\n", sqlite.SchemaVersion)
	fmt.Printf("wire:     %s\n", joinInts(wireVersions))
	return 0
}

func joinInts(v []int) string {
	s := ""
	for i, n := range v {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprint(n)
	}
	return s
}
