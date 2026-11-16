// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Load reads user-supplied controls from a YAML file or a directory of
// YAML files. It uses the same multi-document schema as the embedded
// catalog, validates every control, and returns a flat list (no category
// grouping — user controls aren't categorised).
func Load(path string) ([]*Control, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return loadDir(path)
	}
	return loadFile(path)
}

// Parse reads user-supplied controls from YAML held in memory, for
// callers with no file to point Load at: a host with no filesystem,
// such as js/wasm in a browser, or controls received over the network.
// The data is what one controls file holds, a control per YAML
// document, and every control is validated as Load validates it. Data
// with no control in it yields an empty list.
func Parse(data []byte) ([]*Control, error) {
	ctrls, err := parseYAML(data)
	if err != nil {
		return nil, fmt.Errorf("parsing controls: %w", err)
	}
	for _, c := range ctrls {
		if vErr := c.Validate(); vErr != nil {
			return nil, fmt.Errorf("invalid control: %w", vErr)
		}
		if vErr := validateTrack(c); vErr != nil {
			return nil, fmt.Errorf("invalid control: %w", vErr)
		}
	}
	return ctrls, nil
}

func loadFile(path string) ([]*Control, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	ctrls, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ctrls, nil
}

func loadDir(root string) ([]*Control, error) {
	var out []*Control
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}
		ctrls, lErr := loadFile(p)
		if lErr != nil {
			return lErr
		}
		out = append(out, ctrls...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return out, nil
}
