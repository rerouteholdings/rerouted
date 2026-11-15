package keyd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// MakeBundle brings a key bundle up to date: old (empty for none) with the key files found
// in the import directories (a data directory from before rerouted-keyd), and new keys for
// any still missing. Keys already in the bundle are kept, those of communities no longer
// configured too. It answers the new bundle and the files that are now in it, which can be
// deleted. A file that differs from the bundle's is an error: nothing is replaced.
func MakeBundle(old []byte, imports []string, name string, cms []string) ([]byte, []string, error) {
	bd := bundle{}
	if len(bytes.TrimSpace(old)) > 0 {
		if err := wire.Unmarshal(old, &bd); err != nil {
			return nil, nil, fmt.Errorf("keyd: unreadable key bundle: %w", err)
		}
	}
	var done []string
	for _, f := range Files(name, cms) {
		for _, dir := range imports {
			path := filepath.Join(dir, f)
			b, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			if err := checkFile(f, b); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", path, err)
			}
			c, _ := wire.Canonical(b)
			if have := bd[f]; have != nil {
				if h, _ := wire.Canonical(have); !bytes.Equal(h, c) {
					return nil, nil, fmt.Errorf("keyd: %s isn't the %s in the bundle: move one of them away", path, f)
				}
			} else {
				bd[f] = c
			}
			done = append(done, path)
		}
		if bd[f] == nil {
			b, err := serverkey.Generate(f)
			if err != nil {
				return nil, nil, err
			}
			bd[f] = b
		}
	}
	for f, b := range bd {
		if err := checkFile(f, b); err != nil {
			return nil, nil, fmt.Errorf("keyd: %s in the bundle: %w", f, err)
		}
	}
	out, err := wire.Marshal(bd)
	return out, done, err
}

func checkFile(name string, b []byte) error {
	if name == serverkey.FileV1 {
		_, err := serverkey.ParseV1(b)
		return err
	}
	_, err := serverkey.ParseComposite(b)
	return err
}

// Unbundle writes a bundle's key files into dir, for going back to keys in rerouted's data
// directory, or for a backup that doesn't depend on this machine. Existing files are kept.
func Unbundle(b []byte, dir string) error {
	var bd bundle
	if err := wire.Unmarshal(b, &bd); err != nil {
		return fmt.Errorf("keyd: unreadable key bundle: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for f, data := range bd {
		if filepath.Base(f) != f || checkFile(f, data) != nil {
			return fmt.Errorf("keyd: %q in the bundle isn't a key file", f)
		}
		fd, err := os.OpenFile(filepath.Join(dir, f), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = fd.Write(data)
		if cerr := fd.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}
