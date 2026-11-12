// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Sensitive-path file open observation (metadata only — no content).
#include "kavach_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Tracepoint: sys_enter_openat — observe path+pid; never block. */
SEC("tracepoint/syscalls/sys_enter_openat")
int kavach_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct kavach_event *e;
	const char *filename = (const char *)ctx->args[1];

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_FILE;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	if (filename)
		bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
