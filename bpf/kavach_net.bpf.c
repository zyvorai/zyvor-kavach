// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Host connect observation (pid+tuple). Never drop or redirect packets.
// Cluster datapath enforce stays with Netra — Kavach only reports.
#include "kavach_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int kavach_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_NET;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->protocol = 6; /* TCP best-effort; sockaddr decode is userspace/enrichment */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
