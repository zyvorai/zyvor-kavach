// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import "runtime"

// SensorBackend describes which process sensor is active.
type SensorBackend string

const (
	SensorProcPoll      SensorBackend = "proc-poll"
	SensorProcConnector SensorBackend = "proc-connector"
	SensorEBPF          SensorBackend = "ebpf-sched-process-exec"
)

// ProbeSensor reports the best available sensor on this host.
// Full CO-RE eBPF programs live under bpf/ and load only on Linux with CAP_BPF;
// this stub documents capability and returns the portable fallback.
func ProbeSensor() SensorBackend {
	if runtime.GOOS != "linux" {
		return SensorProcPoll
	}
	if ebpfAvailable() {
		return SensorEBPF
	}
	return SensorProcConnector
}

// ebpfAvailable is overridden on linux with build tag; default false.
var ebpfAvailable = func() bool { return false }
