// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
//go:build linux

package edr

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// WatchEBPF attempts to open a pinned Kavach exec ringbuf if present.
// Full CO-RE loading still requires installing kavach_exec.o via bpftool/clang.
// When unavailable, callers fall back to WatchExec (proc connector) + poll.
func WatchEBPF(ctx context.Context) (<-chan int, error) {
	pin := firstNonEmpty(
		os.Getenv("KAVACH_BPF_PIN"),
		"/sys/fs/bpf/kavach/events",
		"/sys/fs/bpf/kavach_events",
	)
	f, err := os.Open(pin)
	if err != nil {
		return nil, err
	}
	ch := make(chan int, 64)
	go func() {
		defer close(ch)
		defer f.Close()
		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = f.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := f.Read(buf)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				return
			}
			// Best-effort: first 4 bytes as pid if framed loosely.
			if n >= 4 {
				pid := int(binary.LittleEndian.Uint32(buf[:4]))
				if pid > 1 {
					select {
					case ch <- pid:
					default:
					}
				}
			}
		}
	}()
	return ch, nil
}

func findBPFObject() string {
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
			return c
		}
	}
	return ""
}
