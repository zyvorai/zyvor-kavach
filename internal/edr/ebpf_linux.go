// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//go:build linux

package edr

import (
	"os"
	"path/filepath"
)

func init() {
	ebpfAvailable = func() bool {
		// Lab check: packaged BPF object present and bpf fs mounted.
		if _, err := os.Stat("/sys/fs/bpf"); err != nil {
			return false
		}
		candidates := []string{
			"bpf/kavach_exec.o",
			"/usr/lib/kavach/bpf/kavach_exec.o",
			filepath.Join(os.Getenv("KAVACH_BPF_OBJ"), "kavach_exec.o"),
		}
		for _, c := range candidates {
			if c == "" || c == "kavach_exec.o" {
				continue
			}
			if _, err := os.Stat(c); err == nil {
				return true
			}
		}
		return false
	}
}
