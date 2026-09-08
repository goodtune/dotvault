package dockervol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// stateFile is the persisted form of the registry: definitions and mount
// references, never secret data. It is what lets a daemon restart under a
// running container resume refreshing the directory the container still
// has, rather than finding an unknown volume when the engine next asks.
type stateFile struct {
	Volumes []persistedVolume `json:"volumes"`
}

type persistedVolume struct {
	Name   string            `json:"name"`
	Opts   map[string]string `json:"opts,omitempty"`
	Spec   Spec              `json:"spec"`
	Mounts []string          `json:"mounts,omitempty"`
}

// load reads the state file into the registry. A missing file is an empty
// registry; a corrupt one is an error, since silently starting empty would
// make every engine-known volume unmountable with no explanation.
func (d *Driver) load() error {
	data, err := os.ReadFile(d.opts.StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("dockervol: read state %s: %w", d.opts.StatePath, err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("dockervol: parse state %s: %w", d.opts.StatePath, err)
	}
	for _, pv := range st.Volumes {
		if err := ValidateName(pv.Name); err != nil {
			return fmt.Errorf("dockervol: state %s: %w", d.opts.StatePath, err)
		}
		if pv.Spec.TTL <= 0 {
			pv.Spec.TTL = d.opts.DefaultTTL
		}
		if pv.Spec.Layout == "" {
			pv.Spec.Layout = LayoutJSON
		}
		if pv.Spec.Mode == 0 {
			pv.Spec.Mode = DefaultMode
		}
		v := &volume{Name: pv.Name, Opts: pv.Opts, Spec: pv.Spec, Mounts: map[string]bool{}}
		for _, id := range pv.Mounts {
			v.Mounts[id] = true
		}
		d.volumes[pv.Name] = v
	}
	return nil
}

// saveLocked writes the registry atomically at 0600. Caller holds d.mu.
func (d *Driver) saveLocked() error {
	st := stateFile{Volumes: make([]persistedVolume, 0, len(d.volumes))}
	for _, v := range d.volumes {
		pv := persistedVolume{Name: v.Name, Opts: v.Opts, Spec: v.Spec}
		for id := range v.Mounts {
			pv.Mounts = append(pv.Mounts, id)
		}
		sort.Strings(pv.Mounts)
		st.Volumes = append(st.Volumes, pv)
	}
	sort.Slice(st.Volumes, func(i, j int) bool { return st.Volumes[i].Name < st.Volumes[j].Name })

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("dockervol: encode state: %w", err)
	}
	dir := filepath.Dir(d.opts.StatePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("dockervol: create state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".docker-volumes-*")
	if err != nil {
		return fmt.Errorf("dockervol: write state: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("dockervol: write state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("dockervol: write state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("dockervol: write state: %w", err)
	}
	if err := os.Rename(name, d.opts.StatePath); err != nil {
		os.Remove(name)
		return fmt.Errorf("dockervol: write state: %w", err)
	}
	return nil
}
