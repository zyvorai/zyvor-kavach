// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Fork / exit observation. Never kill or isolate.
#include "kavach_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tp_btf/sched_process_fork")
int BPF_PROG(kavach_sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_FORK;
	e->pid = BPF_CORE_READ(child, tgid);
	e->ppid = BPF_CORE_READ(parent, tgid);
	e->uid = bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_core_read_str(&e->comm, sizeof(e->comm), &child->comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(kavach_sched_process_exit, struct task_struct *p)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_EXIT;
	e->pid = BPF_CORE_READ(p, tgid);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->uid = bpf_get_current_uid_gid();
	e->ret = BPF_CORE_READ(p, exit_code);
	bpf_core_read_str(&e->comm, sizeof(e->comm), &p->comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
