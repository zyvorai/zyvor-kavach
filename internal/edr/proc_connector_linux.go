//go:build linux

package edr

import (
	"context"
	"encoding/binary"
	"errors"
	"syscall"
)

// WatchExec subscribes to Linux proc connector exec notifications.
// Requires kernel CONFIG_PROC_EVENTS and appropriate capabilities. The kernel
// may disable the connector; in that case the caller must use polling fallback.
func WatchExec(ctx context.Context) (<-chan int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, 11) // NETLINK_CONNECTOR
	if err != nil {
		return nil, err
	}
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	// nlmsghdr(16) + cn_msg(20) + PROC_CN_MCAST_LISTEN(4)
	msg := make([]byte, 40)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], 3)   // NLMSG_DONE
	binary.NativeEndian.PutUint32(msg[16:20], 1) // CN_IDX_PROC
	binary.NativeEndian.PutUint32(msg[20:24], 1) // CN_VAL_PROC
	binary.NativeEndian.PutUint16(msg[32:34], 4)
	binary.NativeEndian.PutUint32(msg[36:40], 1) // PROC_CN_MCAST_LISTEN
	if err = syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	out := make(chan int, 256)
	go func() {
		defer close(out)
		defer syscall.Close(fd)
		go func() { <-ctx.Done(); syscall.Shutdown(fd, syscall.SHUT_RD) }()
		buf := make([]byte, 8192)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil || n < 56 {
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					return
				}
				continue
			}
			for pos := 0; pos+56 <= n; {
				length := int(binary.NativeEndian.Uint32(buf[pos : pos+4]))
				if length < 56 || pos+length > n {
					break
				}
				payload := pos + 36
				// proc_event.what=PROC_EVENT_EXEC(0x2), then pid at +16
				if binary.NativeEndian.Uint32(buf[payload:payload+4]) == 2 {
					pid := int(binary.NativeEndian.Uint32(buf[payload+16 : payload+20]))
					if pid > 0 {
						select {
						case out <- pid:
						default:
						}
					}
				}
				pos += (length + 3) &^ 3
			}
		}
	}()
	return out, nil
}

var _ = errors.New // keep errors available for future connector capability checks
