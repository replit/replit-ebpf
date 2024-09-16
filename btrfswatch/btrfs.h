/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BTRFS_H__
#define __BTRFS_H__

// Extracted from vmlinux.h generated via:
// sudo bpftool btf dump file /sys/kernel/btf/btrfs format c > vmlinux.h
//
// The generated vmlinux.h is very large, and we only need a few btrfs structs that are
// not included in traditional linux headers.
//
// This works because we are using BTF + CO-RE which allows the kernel to determine
// struct offsets when the program is loaded.
//
// If these fields are ever removed in future versions of the kernel, this program may 
// stop working.
//
// Read more: https://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html

typedef unsigned int __u32;

typedef __u32 u32;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

struct block_device {
	dev_t bd_dev;
};

struct btrfs_device {
	struct block_device *bdev;
};

struct btrfs_fs_devices {
	struct btrfs_device *latest_dev;
};

struct btrfs_fs_info {
	struct btrfs_super_block *super_copy;
	struct btrfs_fs_devices *fs_devices;
};

struct btrfs_root {
	struct btrfs_fs_info *fs_info;
};

#endif /* __BTRFS_H__ */
