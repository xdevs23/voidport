// SPDX-License-Identifier: GPL-2.0

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_struct.h>
#include <linux/filelock.h>
#include <linux/highmem.h>
#include <linux/jiffies.h>
#include <linux/net.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/scatterlist.h>
#include <linux/signal.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <uapi/linux/virtio_fs.h>
#include <uapi/linux/virtio_ring.h>
#include "../compat.h"
#include "voidport_helpers.h"

/* HZ and MAX_JIFFY_OFFSET are configuration-dependent macros. */
unsigned int voidport_hz(void)
{
	return HZ;
}

unsigned long voidport_max_jiffy_offset(void)
{
	return MAX_JIFFY_OFFSET;
}

/* errorfc is a variadic diagnostic macro over the context log. */
void voidport_fc_error(struct fs_context *fc, const char *message)
{
	errorfc(fc, "%s", message);
}

/* allow_kernel_signal is a static inline over the current task's handlers. */
void voidport_allow_cancel(void)
{
	allow_kernel_signal(SIGKILL);
}

/*
 * current is a macro and is_global_init a static inline. User space cannot
 * send a kernel thread a signal, signal delivery skips a task that is already
 * exiting, and the initial task ignores SIGKILL: a killable wait of any of
 * them never ends at a fatal signal.
 */
bool voidport_current_killable(void)
{
	return !(current->flags & (PF_KTHREAD | PF_EXITING)) &&
	       !is_global_init(current);
}

/* current is a macro and fatal_signal_pending a static inline. */
bool voidport_fatal_signal_pending(void)
{
	return fatal_signal_pending(current);
}

/*
 * siginitsetinv and sigmask are inline and macro. The set leaves out SIGKILL,
 * which sigprocmask never blocks either way.
 */
void voidport_block_signals(sigset_t *saved)
{
	sigset_t blocked;

	siginitsetinv(&blocked, sigmask(SIGKILL));
	sigprocmask(SIG_BLOCK, &blocked, saved);
}

struct folio *voidport_readahead_folio(struct readahead_control *rac)
{
	return readahead_folio(rac);
}

loff_t voidport_folio_pos(const struct folio *folio)
{
	return folio_pos(folio);
}

size_t voidport_folio_size(const struct folio *folio)
{
	return folio_size(folio);
}

void *voidport_kmap_local_folio(struct folio *folio, size_t offset)
{
	return kmap_local_folio(folio, offset);
}

/* Macro or inline according to the architecture's cache-coherence API. */
void voidport_flush_dcache_folio(struct folio *folio)
{
	flush_dcache_folio(folio);
}

/*
 * mapping_gfp_mask and the FGP flags are inline and macros. A folio that is
 * absent and not to be created, or that cannot be allocated, is an error
 * pointer.
 */
struct folio *voidport_write_folio(struct address_space *mapping,
				   pgoff_t index, bool create)
{
	return __filemap_get_folio(mapping, index,
				   FGP_LOCK | (create ? FGP_CREAT : 0),
				   mapping_gfp_mask(mapping));
}

bool voidport_folio_test_uptodate(struct folio *folio)
{
	return folio_test_uptodate(folio);
}

void voidport_folio_mark_uptodate(struct folio *folio)
{
	folio_mark_uptodate(folio);
}

/* A folio that is absent is an error pointer. */
struct folio *voidport_get_folio(struct address_space *mapping, pgoff_t index)
{
	return filemap_get_folio(mapping, index);
}

void voidport_folio_put(struct folio *folio)
{
	folio_put(folio);
}

/* Writeback errors and the page cache tags are static inlines. */
void voidport_mapping_set_error(struct address_space *mapping, int error)
{
	mapping_set_error(mapping, error);
}

bool voidport_mapping_dirty(struct address_space *mapping)
{
	return mapping_tagged(mapping, PAGECACHE_TAG_DIRTY);
}

bool voidport_mapping_writeback(struct address_space *mapping)
{
	return mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK);
}

/* iov_iter_extract_will_pin is a static inline over the iterator. */
bool voidport_iov_iter_extract_will_pin(const struct iov_iter *iter)
{
	return iov_iter_extract_will_pin(iter);
}

/* generic_write_sync is a static inline over vfs_fsync_range. */
ssize_t voidport_write_sync(struct kiocb *iocb, ssize_t count)
{
	return generic_write_sync(iocb, count);
}

loff_t voidport_i_size_read(const struct inode *inode)
{
	return i_size_read(inode);
}

void voidport_i_size_write(struct inode *inode, loff_t size)
{
	i_size_write(inode, size);
}

void voidport_inode_set_times(struct inode *inode, struct timespec64 atime,
			      struct timespec64 mtime, struct timespec64 ctime)
{
	inode_set_atime_to_ts(inode, atime);
	inode_set_mtime_to_ts(inode, mtime);
	inode_set_ctime_to_ts(inode, ctime);
}

/* Compatibility selects an inline accessor or READ_ONCE on the older ABI. */
bool voidport_inode_is_new(struct inode *inode)
{
	return voidport_inode_state(inode) & I_NEW;
}

/* The device number encoding of a stat is a static inline. */
dev_t voidport_new_decode_dev(u32 dev)
{
	return new_decode_dev(dev);
}

/* d_in_lookup is a static inline over the dentry flags. */
bool voidport_d_in_lookup(const struct dentry *dentry)
{
	return d_in_lookup(dentry);
}

/* current_umask is a static inline over the task's filesystem context. */
unsigned int voidport_current_umask(void)
{
	return current_umask();
}

/* ACL_DONT_CACHE is a pointer-cast macro. */
void voidport_inode_uncache_acls(struct inode *inode)
{
	inode->i_acl = ACL_DONT_CACHE;
	inode->i_default_acl = ACL_DONT_CACHE;
}

void *voidport_posix_acl_to_xattr(const struct posix_acl *acl, size_t *size)
{
	return voidport_posix_acl_value(acl, size);
}

/* posix_acl_xattr_name is a static inline. */
const char *voidport_posix_acl_xattr_name(int type)
{
	return posix_acl_xattr_name(type);
}

/* Page-cache addressability is a kernel macro. */
loff_t voidport_max_lfs_filesize(void)
{
	return MAX_LFS_FILESIZE;
}

/* Directory emission is static inline, including the dot-entry handling. */
bool voidport_dir_emit_dots(struct file *file, struct dir_context *ctx)
{
	return dir_emit_dots(file, ctx);
}

bool voidport_dir_emit(struct dir_context *ctx, const char *name, int len,
		       u64 ino, unsigned int type)
{
	return dir_emit(ctx, name, len, ino, type);
}

/*
 * struct file_lock has a layout that structure randomization may reorder,
 * which a generated binding cannot follow.
 */
struct voidport_record_lock voidport_lock_read(const struct file_lock *fl)
{
	return (struct voidport_record_lock){
		.start = fl->fl_start,
		.end = fl->fl_end,
		.owner = fl->c.flc_owner,
		.pid = fl->c.flc_pid,
		.type = fl->c.flc_type,
		.sleep = fl->c.flc_flags & FL_SLEEP,
		.deferred_grant = fl->fl_lmops && fl->fl_lmops->lm_grant,
	};
}

/*
 * A socket wakes the tasks that wait for room to send in an interruptible
 * sleep. This entry passes each wakeup on to a sleep that no signal ends.
 */
static int voidport_wake_sleeper(struct wait_queue_entry *wait,
				 unsigned int mode, int sync, void *key)
{
	return woken_wake_function(wait, TASK_NORMAL, sync, key);
}

/* init_wait_func and sk_sleep are a macro and a static inline. */
struct wait_queue_head *voidport_socket_wait_add(struct socket *sock,
						 struct wait_queue_entry *wait)
{
	init_wait_func(wait, voidport_wake_sleeper);
	add_wait_queue(sk_sleep(sock->sk), wait);
	return sk_sleep(sock->sk);
}

/*
 * TASK_KILLABLE and MAX_SCHEDULE_TIMEOUT are macros, current a macro and
 * fatal_signal_pending a static inline. Returns whether a fatal signal is
 * pending after the wait.
 */
bool voidport_wait_woken_killable(struct wait_queue_entry *wait)
{
	wait_woken(wait, TASK_KILLABLE, MAX_SCHEDULE_TIMEOUT);
	return fatal_signal_pending(current);
}

/* IS_GETLK is a macro over the 32-bit and the 64-bit test commands. */
bool voidport_lock_is_getlk(int cmd)
{
	return IS_GETLK(cmd);
}

void voidport_lock_conflict(struct file_lock *fl,
			    struct voidport_record_lock conflict)
{
	fl->fl_start = conflict.start;
	fl->fl_end = conflict.end;
	fl->c.flc_pid = conflict.pid;
	fl->c.flc_type = conflict.type;
}

/* The reclaim scope uses task-local static-inline accessors. */
unsigned int voidport_nofs_save(void)
{
	return memalloc_nofs_save();
}

void voidport_nofs_restore(unsigned int flags)
{
	memalloc_nofs_restore(flags);
}

/*
 * Kernel macros initialize the states and supply the call site's identity.
 * Each diagnostic class has its own state, so a flapping connection cannot
 * silence a cleanup accounting line. An unknown class is never silenced.
 */
bool voidport_ratelimited(unsigned int class)
{
	static DEFINE_RATELIMIT_STATE(transport, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	static DEFINE_RATELIMIT_STATE(protocol, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	static DEFINE_RATELIMIT_STATE(cleanup, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	static DEFINE_RATELIMIT_STATE(cache, DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	struct ratelimit_state *states[] = { &transport, &protocol, &cleanup,
					     &cache };

	if (class >= ARRAY_SIZE(states))
		return true;
	return __ratelimit(states[class]);
}

/* Namespace references are counted by static-inline get_net and put_net. */
struct net *voidport_get_net(struct net *net)
{
	return get_net(net);
}

void voidport_put_net(struct net *net)
{
	put_net(net);
}

/*
 * A unix connect resolves its path against the root of the calling task.
 * Kernels that start kernel threads in an empty root of their own provide
 * the scoped_with_init_fs macro, which lends the task the root of init for
 * the scope. On kernels without it, kernel threads share the root of init.
 */
int voidport_connect_from_init_root(struct socket *sock,
				    struct sockaddr_storage *address, int len)
{
	int ret;

#ifdef scoped_with_init_fs
	scoped_with_init_fs()
		ret = kernel_connect(sock, (void *)address, len, 0);
#else
	ret = kernel_connect(sock, (void *)address, len, 0);
#endif
	return ret;
}

int voidport_virtio_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
			     struct virtqueue *vqs[],
			     struct virtqueue_info info[])
{
	return virtio_find_vqs(vdev, nvqs, vqs, info, NULL);
}

void voidport_virtio_device_ready(struct virtio_device *vdev)
{
	virtio_device_ready(vdev);
}

/*
 * The private pointer of a device points to the record of the driver for the
 * device. The private pointer of each queue is for the transport, which stores
 * the address of the notification register of the queue there.
 */
void voidport_virtio_set_driver_data(struct virtio_device *vdev, void *data)
{
	vdev->priv = data;
}

void *voidport_virtio_driver_data(struct virtio_device *vdev)
{
	return vdev->priv;
}

void voidport_virtio_del_vqs(struct virtio_device *vdev)
{
	vdev->config->del_vqs(vdev);
}

/* Whether the queues of the device take a chain as one indirect descriptor. */
bool voidport_virtio_indirect(struct virtio_device *vdev)
{
	return virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC);
}

/*
 * The workqueue allocated by the virtio driver: unbound, with a rescuer thread
 * that runs its work when memory is too short to start a new worker.
 */
struct workqueue_struct *voidport_virtio_alloc_workqueue(void)
{
	return alloc_workqueue("voidport", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
}

void voidport_virtio_fs_tag(struct virtio_device *vdev, u8 *tag)
{
	virtio_cread_bytes(vdev, offsetof(struct virtio_fs_config, tag), tag,
			   sizeof_field(struct virtio_fs_config, tag));
}

u32 voidport_virtio_fs_queues(struct virtio_device *vdev)
{
	u32 queues;

	virtio_cread_le(vdev, struct virtio_fs_config, num_request_queues,
			&queues);
	return queues;
}

/* The pages a descriptor chain lists, and the references it has to them. */
void voidport_sg_set_page(struct scatterlist *sg, struct page *page,
			  unsigned int len, unsigned int offset)
{
	sg_set_page(sg, page, len, offset);
}

struct page *voidport_folio_page(struct folio *folio, unsigned long index)
{
	return folio_page(folio, index);
}

void voidport_get_page(struct page *page)
{
	get_page(page);
}

void voidport_put_page(struct page *page)
{
	put_page(page);
}
