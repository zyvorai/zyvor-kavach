// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Kavach sched_process_exec observation (CO-RE). Detect/report only.
#include "kavach_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} lost_events SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(kavach_sched_process_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct kavach_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 z = 0;
		__u64 *c = bpf_map_lookup_elem(&lost_events, &z);
		if (c)
			__sync_fetch_and_add(c, 1);
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->type = KAVACH_EVT_EXEC;
	e->pid = BPF_CORE_READ(p, tgid);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->uid = bpf_get_current_uid_gid();
	e->gid = bpf_get_current_uid_gid() >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_core_read_str(&e->comm, sizeof(e->comm), &p->comm);
	if (bprm)
		bpf_core_read_str(&e->path, sizeof(e->path), &bprm->filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
