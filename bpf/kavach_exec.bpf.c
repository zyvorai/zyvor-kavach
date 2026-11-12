// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
// Kavach sched_process_exec observation scaffold (CO-RE).
// Build on Linux with clang -target bpf. Not loaded from macOS builds.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct exec_event {
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(kavach_sched_process_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = BPF_CORE_READ(p, tgid);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->uid = bpf_get_current_uid_gid();
	bpf_core_read_str(&e->comm, sizeof(e->comm), &p->comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
