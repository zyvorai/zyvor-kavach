/* SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0 */
/* Shared types for Kavach observation-only CO-RE programs. Never enforce. */
#ifndef KAVACH_COMMON_H
#define KAVACH_COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define KAVACH_EVT_EXEC   1
#define KAVACH_EVT_FORK   2
#define KAVACH_EVT_EXIT   3
#define KAVACH_EVT_FILE   4
#define KAVACH_EVT_PRIV   5
#define KAVACH_EVT_NET    6
#define KAVACH_EVT_MEMFD  7
#define KAVACH_EVT_PTRACE 8
#define KAVACH_EVT_MODULE 9
#define KAVACH_EVT_BPF    10

struct kavach_event {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 ret;
	__u64 cgroup_id;
	char  comm[16];
	char  path[128];
	__u32 daddr;
	__u16 dport;
	__u16 sport;
	__u8  protocol;
	__u8  _pad[3];
};

#endif /* KAVACH_COMMON_H */
