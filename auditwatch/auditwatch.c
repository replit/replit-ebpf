/* SPDX-License-Identifier: GPL-2.0 */
//go:build ignore

#include "audit.h"
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/btrfs_tree.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    u64 cgroup_id;
    u32 pid;
    unsigned char path[512];
};

/*
 * registered_cgroups keeps track of the cgroups that should be watched for apparmor
 * denials. The value should always be set to `true`.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // Use an LRU just in case entries get leaked.
    __type(key, u64);
    __type(value, bool);
    __uint(max_entries, 1024);
} registered_cgroups SEC(".maps");

/*
 * apparmor_denials is a ringbuffer used for sending denial messages back
 * to the userspace process.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
    __type(value, struct event);
} apparmor_denials SEC(".maps");


SEC("kprobe/common_lsm_audit")
int BPF_KPROBE(
    common_lsm_audit,
    struct common_audit_data *cad,
    void (*pre_auditcb) (struct audit_buffer *, void *),
    void (*post_audit) (struct audit_buffer *, void *)
) {
    int type;

    // This is a bit spooky to do because the `common_audit_data` stores a union
    // of all the per-LSM audit data. As of Linux 6.12, it only holds smack, SELinux,
    // and AppArmor, and only AppArmor is enabled in production. We'll take a big leap
    // of faith.
    struct apparmor_audit_data *ad;
    BPF_CORE_READ_INTO(&ad, cad, apparmor_audit_data);
    if (ad == NULL) {
        return 0;
    }

    // Don't report if it's not a denial.
    BPF_CORE_READ_INTO(&type, ad, type);
    if (type != AUDIT_APPARMOR_DENIED && type != AUDIT_APPARMOR_KILL) {
        return 0;
    }

    const u64 cgroup_id = bpf_get_current_cgroup_id();
    const u64 tgid = bpf_get_current_pid_tgid();

    bool *registered = bpf_map_lookup_elem(&registered_cgroups, &cgroup_id);
    if (registered == NULL || !*registered) {
        return 0;
    }

    struct event *evt_buf = bpf_ringbuf_reserve(&apparmor_denials, sizeof(struct event), 0);
    if (!evt_buf) {
        return 0;
    }

    evt_buf->cgroup_id = cgroup_id;
    evt_buf->pid = tgid & 0xffffffff;
    char *name;
    BPF_CORE_READ_INTO(&name, ad, name);
    if (name != NULL) {
        // Some events don't have a name.
        bpf_probe_read_kernel_str(evt_buf->path, sizeof(evt_buf->path), name);
    }
    bpf_ringbuf_submit(evt_buf, BPF_RB_FORCE_WAKEUP);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
