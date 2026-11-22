// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
//go:build !linux

package edr

import (
	"context"
	"errors"
)

func WatchEBPF(ctx context.Context) (<-chan int, error) {
	return nil, errors.New("eBPF watch unavailable on this platform")
}
