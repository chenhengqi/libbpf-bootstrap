// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct connection {
	int xx;
	long yy;
	short zz;
};

SEC("uprobe/func")
int BPF_KPROBE(uprobe, struct connection *conn)
{
	struct connection c = {};

	bpf_probe_read_user(&c, sizeof(c), conn);
	bpf_printk("UPROBE ENTRY: fd = %d, fd = %ld\n", c.xx, c.yy);
	return 0;
}

SEC("uretprobe/func")
int BPF_KRETPROBE(uretprobe, int ret)
{
	bpf_printk("UPROBE EXIT: return = %d\n", ret);
	return 0;
}
