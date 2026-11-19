package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The packages ship these units disabled: the timer runs the service daily, and the
// service upgrades the rerouted package alone from the Reroute repository.
const (
	updateTimer   = "rerouted-update.timer"
	updateService = "rerouted-update.service"
)

// Swapped by tests.
var (
	osReleaseFile  = "/etc/os-release"
	packagedBinary = "/usr/bin/rerouted"
	executable     = os.Executable
	sysRun         = func(name string, args ...string) (string, error) {
		out, err := exec.Command(name, args...).CombinedOutput()
		return string(out), err
	}
	sysRoot = isRoot
)

// osRelease reads /etc/os-release's ID and ID_LIKE, lowercased, as one list.
func osRelease() []string {
	f, err := os.Open(osReleaseFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && (k == "ID" || k == "ID_LIKE") {
			ids = append(ids, strings.Fields(strings.ToLower(strings.Trim(v, `"'`)))...)
		}
	}
	return ids
}

// packageOwner reports which package manager owns the packaged binary, or "".
func packageOwner() string {
	if _, err := sysRun("dpkg", "-S", packagedBinary); err == nil {
		return "dpkg"
	}
	if _, err := sysRun("rpm", "-qf", packagedBinary); err == nil {
		return "rpm"
	}
	return ""
}

func runAutoUpdates(_ *globals, args []string) int {
	return autoUpdates(os.Stdout, os.Stderr, args[1:])
}

func autoUpdates(stdout, stderr io.Writer, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: rerouted auto-updates on|off|status")
		return 2
	}
	switch args[0] {
	case "status":
		return autoUpdateStatus(stdout, stderr)
	case "on", "off":
	default:
		fmt.Fprintln(stderr, "usage: rerouted auto-updates on|off|status")
		return 2
	}
	on := args[0] == "on"
	if on {
		for _, id := range osRelease() {
			switch id {
			case "arch":
				fmt.Fprintln(stderr, "Automatic updates aren't available on Arch Linux and its derivatives: pacman doesn't\n"+
					"support upgrading one package alone (a partial upgrade can break the system). Update\n"+
					"rerouted with the rest of the system, with pacman -Syu.")
				return 1
			case "gentoo":
				fmt.Fprintln(stderr, "Automatic updates aren't available on Gentoo: update rerouted with the rest of the system,\n"+
					"with emerge.")
				return 1
			}
		}
		self, err := executable()
		if err == nil {
			self, _ = filepath.EvalSymlinks(self)
		}
		want, werr := filepath.EvalSymlinks(packagedBinary)
		if werr != nil || self != want {
			fmt.Fprintf(stderr, "This rerouted is %s, not the package's %s. Automatic updates only update the\n"+
				"rerouted package from the Reroute repository: install it that way first (docs/run-a-homeserver.md).\n", self, packagedBinary)
			return 1
		}
		if packageOwner() == "" {
			fmt.Fprintf(stderr, "No package owns %s (neither dpkg nor rpm knows it), so there's no package to update.\n"+
				"Install rerouted from the Reroute repository first (docs/run-a-homeserver.md).\n", packagedBinary)
			return 1
		}
		if _, err := sysRun("systemctl", "cat", updateTimer); err != nil {
			fmt.Fprintf(stderr, "The installed package has no %s: update the rerouted package first.\n", updateTimer)
			return 1
		}
	}
	if !sysRoot() {
		fmt.Fprintf(stderr, "Turning automatic updates %s needs root: sudo rerouted auto-updates %s\n", args[0], args[0])
		return 1
	}
	verb := "disable"
	if on {
		verb = "enable"
	}
	if out, err := sysRun("systemctl", verb, "--now", updateTimer); err != nil {
		fmt.Fprintf(stderr, "systemctl %s --now %s: %v\n%s", verb, updateTimer, err, out)
		return 1
	}
	if on {
		fmt.Fprintln(stdout, "Automatic updates are on: once a day, the rerouted package alone is upgraded from the\n"+
			"Reroute repository, and rerouted restarts once no calls are active.\n"+
			"See what happened with rerouted auto-updates status, or journalctl -u "+updateService+".")
	} else {
		fmt.Fprintln(stdout, "Automatic updates are off. Update rerouted with your package manager.")
	}
	return 0
}

// systemdProps reads systemctl show's KEY=value lines.
func systemdProps(unit string, props ...string) (map[string]string, error) {
	out, err := sysRun("systemctl", "show", unit, "--property="+strings.Join(props, ","))
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %v %s", unit, err, strings.TrimSpace(out))
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m, nil
}

func autoUpdateStatus(stdout, stderr io.Writer) int {
	t, err := systemdProps(updateTimer, "LoadState", "UnitFileState", "ActiveState", "LastTriggerUSec", "NextElapseUSecRealtime")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if t["LoadState"] == "not-found" {
		fmt.Fprintf(stdout, "automatic updates: not available (%s isn't installed; it comes with the rerouted package)\n", updateTimer)
		return 0
	}
	state := "off"
	if t["UnitFileState"] == "enabled" {
		state = "on"
	}
	fmt.Fprintf(stdout, "automatic updates: %s (%s is %s and %s)\n", state, updateTimer, orDash(t["UnitFileState"]), orDash(t["ActiveState"]))
	if v := t["LastTriggerUSec"]; v != "" && v != "n/a" && v != "0" {
		s, _ := systemdProps(updateService, "Result", "ExecMainStatus")
		fmt.Fprintf(stdout, "last run:          %s (%s)\n", v, orDash(s["Result"]))
	} else {
		fmt.Fprintln(stdout, "last run:          never")
	}
	if v := t["NextElapseUSecRealtime"]; state == "on" && v != "" && v != "n/a" {
		fmt.Fprintf(stdout, "next run:          %s\n", v)
	}
	fmt.Fprintf(stdout, "log:               journalctl -u %s\n", updateService)
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
