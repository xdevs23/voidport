/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VOIDPORT_COMPAT_H
#define VOIDPORT_COMPAT_H

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/namei.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/xattr.h>

/* Bindgen cannot evaluate the typed or cast expressions in these macros. */
#ifdef __BINDGEN__
static const unsigned int VOIDPORT_LOOKUP_RCU = LOOKUP_RCU;
static const unsigned int VOIDPORT_LOOKUP_EXCL = LOOKUP_EXCL;
static const unsigned int VOIDPORT_LOOKUP_REVAL = LOOKUP_REVAL;
static const unsigned int VOIDPORT_LOOKUP_RENAME_TARGET = LOOKUP_RENAME_TARGET;
static const unsigned int VOIDPORT_SB_RDONLY = SB_RDONLY;
static const unsigned int VOIDPORT_SB_POSIXACL = SB_POSIXACL;
static const unsigned int VOIDPORT_FMODE_OPENED = FMODE_OPENED;
static const unsigned int VOIDPORT_FMODE_CREATED = FMODE_CREATED;
static const fmode_t VOIDPORT_FMODE_CAN_ODIRECT = FMODE_CAN_ODIRECT;
#endif

/* struct file_lock may have a randomized layout, so C forwarders copy these. */
struct voidport_record_lock {
	loff_t start;
	loff_t end;
	fl_owner_t owner;
	pid_t pid;
	unsigned char type;
	bool sleep;
	/*
	 * Whether the caller, lockd, asks for a grant that arrives after the
	 * reply, through the lm_grant of its lock manager.
	 */
	bool deferred_grant;
};

/* Longterm kernels predate inode_state_read_once(); read i_state directly. */
static inline unsigned long voidport_inode_state(struct inode *inode)
{
#ifdef VOIDPORT_LEGACY_KERNEL
	return READ_ONCE(inode->i_state);
#else
	return inode_state_read_once(inode);
#endif
}

/*
 * Longterm kernels encode an ACL into a buffer of the caller, and later
 * kernels allocate the buffer. Either way the value returned here comes from
 * kmalloc, in the initial user namespace the mount lives in.
 */
static inline void *voidport_posix_acl_value(const struct posix_acl *acl,
					     size_t *size)
{
#ifdef VOIDPORT_LEGACY_KERNEL
	void *value;

	*size = posix_acl_xattr_size(acl->a_count);
	value = kmalloc(*size, GFP_KERNEL);
	/* A buffer of the exact size cannot be too small, the one failure. */
	if (value)
		posix_acl_to_xattr(&init_user_ns, acl, value, *size);
	return value;
#else
	return posix_acl_to_xattr(&init_user_ns, acl, size, GFP_KERNEL);
#endif
}

#endif /* VOIDPORT_COMPAT_H */
