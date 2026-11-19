// Package status writes the running server's status file, {data dir}/status.json, which
// `rerouted status` and other local tools read. Its shape is fixed: tools depend on it.
package status

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// FileName is the status file's name in the data directory.
const FileName = "status.json"

// Status is the status file's contents. Strings are empty when a feature is off or there's
// nothing to report.
type Status struct {
	Version           string `json:"version"`
	PID               int    `json:"pid"`
	Started           int64  `json:"started"` // Unix seconds
	Updated           int64  `json:"updated"` // Unix seconds
	Name              string `json:"name"`
	Listen            string `json:"listen"`
	VoiceRooms        int    `json:"voice_rooms"`
	VoiceParticipants int    `json:"voice_participants"`
	Outbox            int    `json:"outbox"`
	RestartPending    bool   `json:"restart_pending"`
	UpdateAvailable   string `json:"update_available"` // the newer version, if any
	Metrics           string `json:"metrics"`          // the metrics address, if on
	Turn              string `json:"turn"`             // the built-in call relay's address, if on
}

// Write replaces the status file in dir, atomically: readers see the old file or the new
// one, never part of one.
func Write(dir string, s Status) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".status-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, FileName)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Remove deletes the status file, on a clean shutdown.
func Remove(dir string) error {
	err := os.Remove(filepath.Join(dir, FileName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Read reads the status file in dir.
func Read(dir string) (Status, error) {
	var s Status
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}
