//go:build ignore

#include "btrfs.h"
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/btrfs_tree.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    const __u8 fsid[16];
    const char label[256];
    const dev_t dev_id;
    int ret;
};

/*
 * registered_devices keeps track of the devices that should be watched for btrfs
 * errors. The value should always be set to `true`.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // Use an LRU just in case entries get leaked.
    __type(key, dev_t);
    __type(value, bool);
    __uint(max_entries, 1024);
} registered_devices SEC(".maps");

/*
 * btrfs_recover_log_trees_errors is a ringbuffer used for sending error messages back 
 * to the userspace process.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} btrfs_recover_log_trees_errors SEC(".maps");

/*
 * pending_calls keeps track of in-flight btrfs_recover_log_trees calls.
 *
 * This is required because we can only look up device info in the kprobe but
 * we only have access to the return value in the kretprobe.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, dev_t);
    __type(value, struct event);
    __uint(max_entries, 1024);
} pending_calls SEC(".maps");


SEC("kprobe/btrfs_recover_log_trees")
int BPF_KPROBE(btrfs_recover_log_trees, struct btrfs_root *root_tree) {
    struct event evt;

    // Introspect btrfs structs to find the device major & minor.
    BPF_CORE_READ_INTO(&evt.dev_id, root_tree, fs_info, fs_devices, latest_dev, bdev, bd_dev);
    BPF_CORE_READ_INTO(&evt.label, root_tree, fs_info, super_copy, label);
    BPF_CORE_READ_INTO(&evt.fsid, root_tree, fs_info, super_copy, fsid);

    bool *registered = bpf_map_lookup_elem(&registered_devices, &evt.dev_id);
    if (registered == NULL || !*registered) {
        return 0;
    }

    const u32 tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_calls, &tgid, &evt, BPF_ANY);

    return 0;
}

SEC("kretprobe/btrfs_recover_log_trees")
int BPF_KRETPROBE(btrfs_recover_log_trees_exit, int ret) {
    if (ret >= 0) {
        return 0;
    }

    const u32 tgid = bpf_get_current_pid_tgid();
    struct event *evt = bpf_map_lookup_elem(&pending_calls, &tgid);
    if (evt == NULL) {
        return 0;
    }
    bpf_map_delete_elem(&pending_calls, &tgid);

    evt->ret = ret;

    struct event *evt_buf = bpf_ringbuf_reserve(&btrfs_recover_log_trees_errors, sizeof(struct event), 0);
    if (!evt_buf) {
        return 0;
    }

    __builtin_memcpy(evt_buf, evt, sizeof(struct event));
    bpf_ringbuf_submit(evt_buf, BPF_RB_FORCE_WAKEUP);

    return 0;
}


char __license[] SEC("license") = "Dual MIT/GPL";
