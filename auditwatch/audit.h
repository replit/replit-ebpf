/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __AUDIT_H__
#define __AUDIT_H__

// Extracted from vmlinux.h generated via:
// sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// The generated vmlinux.h is very large, and we only need a few audit structs that are
// not included in traditional linux headers.
//
// This works because we are using BTF + CO-RE which allows the kernel to determine
// struct offsets when the program is loaded.
//
// If these fields are ever removed in future versions of the kernel, this program may
// stop working.
//
// Read more: https://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html

#include <linux/audit.h>
#include <linux/fs.h>
#include <linux/sched.h>

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long unsigned int __u64;

typedef __u8 u8;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __u64 u64;

typedef s32 int32_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef u32 __kernel_dev_t;

typedef int32_t key_serial_t;

typedef __kernel_dev_t dev_t;

typedef unsigned int gfp_t;

typedef short unsigned int umode_t;

typedef struct {
	uid_t val;
} kuid_t;

typedef struct {
	gid_t val;
} kgid_t;

struct selinux_audit_data;

struct apparmor_audit_data;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct common_audit_data {
	char type;
	union {
		struct path path;
		struct dentry *dentry;
		struct inode *inode;
		struct lsm_network_audit *net;
		int cap;
		int ipc_id;
		struct task_struct *tsk;
		struct {
			key_serial_t key;
			char *key_desc;
		} key_struct;
		char *kmod_name;
		struct lsm_ioctlop_audit *op;
		struct file *file;
		struct lsm_ibpkey_audit *ibpkey;
		struct lsm_ibendport_audit *ibendport;
		int reason;
		const char *anonclass;
	} u;
	union {
		struct selinux_audit_data *selinux_audit_data;
		struct apparmor_audit_data *apparmor_audit_data;
	};
};

struct apparmor_audit_data {
	int error;
	int type;
	u16 class;
	const char *op;
	const struct cred *subj_cred;
	struct aa_label *subj_label;
	const char *name;
	const char *info;
	u32 request;
	u32 denied;
	struct task_struct *subjtsk;
	union {
		struct {
			struct aa_label *peer;
			union {
				struct {
					const char *target;
					kuid_t ouid;
				} fs;
				struct {
					int rlim;
					long unsigned int max;
				} rlim;
				struct {
					int signal;
					int unmappedsig;
				};
				struct {
					int type;
					int protocol;
					struct sock *peer_sk;
					void *addr;
					int addrlen;
				} net;
				struct {
					kuid_t ouid;
				} mq;
			};
		};
		struct {
			struct aa_profile *profile;
			const char *ns;
			long int pos;
		} iface;
		struct {
			const char *src_name;
			const char *type;
			const char *trans;
			const char *data;
			long unsigned int flags;
		} mnt;
	};
	struct common_audit_data common;
};

struct audit_buffer;

enum audit_type {
	AUDIT_APPARMOR_AUDIT = 0,
	AUDIT_APPARMOR_ALLOWED = 1,
	AUDIT_APPARMOR_DENIED = 2,
	AUDIT_APPARMOR_HINT = 3,
	AUDIT_APPARMOR_STATUS = 4,
	AUDIT_APPARMOR_ERROR = 5,
	AUDIT_APPARMOR_KILL = 6,
	AUDIT_APPARMOR_USER = 7,
	AUDIT_APPARMOR_AUTO = 8,
};


#endif /* __AUDIT_H__ */
