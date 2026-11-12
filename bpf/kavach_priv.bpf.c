// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Privilege / loader / bpf-abuse observation. Never deny capabilities.
#include "kavach_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_setuid")
int kavach_setuid(struct trace_event_raw_sys_enter *ctx)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_PRIV;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->ret = (__u32)ctx->args[0]; /* target uid */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int kavach_memfd(struct trace_event_raw_sys_enter *ctx)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_MEMFD;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int kavach_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_PTRACE;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->ret = (__u32)ctx->args[0]; /* request */
	e->ppid = (__u32)ctx->args[1]; /* target pid */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int kavach_init_module(struct trace_event_raw_sys_enter *ctx)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_MODULE;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int kavach_bpf_syscall(struct trace_event_raw_sys_enter *ctx)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_BPF;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();
	e->ret = (__u32)ctx->args[0]; /* bpf cmd */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
