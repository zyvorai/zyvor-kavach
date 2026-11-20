//go:build !linux

package edr

import (
	"context"
	"errors"
)

func WatchExec(ctx context.Context) (<-chan int, error) { return nil, errors.New("linux only") }
