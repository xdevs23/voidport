/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VOIDPORT_HELPERS_H
#define VOIDPORT_HELPERS_H

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/signal.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/uio.h>
#include "../compat.h"

struct file_lock;
struct fs_context;
struct net;
struct posix_acl;
struct scatterlist;
struct socket;
struct virtio_device;
struct virtqueue;
struct virtqueue_info;
struct workqueue_struct;

unsigned int voidport_hz(void);
unsigned long voidport_max_jiffy_offset(void);
void voidport_fc_error(struct fs_context *fc, const char *message);
void voidport_allow_cancel(void);
bool voidport_current_killable(void);
bool voidport_fatal_signal_pending(void);
void voidport_block_signals(sigset_t *saved);
struct folio *voidport_readahead_folio(struct readahead_control *rac);
loff_t voidport_folio_pos(const struct folio *folio);
size_t voidport_folio_size(const struct folio *folio);
void *voidport_kmap_local_folio(struct folio *folio, size_t offset);
void voidport_flush_dcache_folio(struct folio *folio);
struct folio *voidport_write_folio(struct address_space *mapping,
				   pgoff_t index, bool create);
bool voidport_folio_test_uptodate(struct folio *folio);
void voidport_folio_mark_uptodate(struct folio *folio);
struct folio *voidport_get_folio(struct address_space *mapping, pgoff_t index);
void voidport_folio_put(struct folio *folio);
void voidport_mapping_set_error(struct address_space *mapping, int error);
bool voidport_mapping_dirty(struct address_space *mapping);
bool voidport_mapping_writeback(struct address_space *mapping);
bool voidport_iov_iter_extract_will_pin(const struct iov_iter *iter);
ssize_t voidport_write_sync(struct kiocb *iocb, ssize_t count);
loff_t voidport_i_size_read(const struct inode *inode);
void voidport_i_size_write(struct inode *inode, loff_t size);
void voidport_inode_set_times(struct inode *inode, struct timespec64 atime,
			      struct timespec64 mtime, struct timespec64 ctime);
bool voidport_inode_is_new(struct inode *inode);
dev_t voidport_new_decode_dev(u32 dev);
bool voidport_d_in_lookup(const struct dentry *dentry);
unsigned int voidport_current_umask(void);
void voidport_inode_uncache_acls(struct inode *inode);
void *voidport_posix_acl_to_xattr(const struct posix_acl *acl, size_t *size);
const char *voidport_posix_acl_xattr_name(int type);
loff_t voidport_max_lfs_filesize(void);
bool voidport_dir_emit_dots(struct file *file, struct dir_context *ctx);
bool voidport_dir_emit(struct dir_context *ctx, const char *name, int len,
		       u64 ino, unsigned int type);
struct voidport_record_lock voidport_lock_read(const struct file_lock *fl);
bool voidport_lock_is_getlk(int cmd);
void voidport_lock_conflict(struct file_lock *fl,
			    struct voidport_record_lock conflict);
unsigned int voidport_nofs_save(void);
void voidport_nofs_restore(unsigned int flags);
bool voidport_ratelimited(unsigned int class);
struct net *voidport_get_net(struct net *net);
void voidport_put_net(struct net *net);
int voidport_connect_from_init_root(struct socket *sock,
				    struct sockaddr_storage *address, int len);
struct wait_queue_head *voidport_socket_wait_add(struct socket *sock,
						 struct wait_queue_entry *wait);
bool voidport_wait_woken_killable(struct wait_queue_entry *wait);
int voidport_virtio_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
			     struct virtqueue *vqs[],
			     struct virtqueue_info info[]);
void voidport_virtio_device_ready(struct virtio_device *vdev);
void voidport_virtio_set_driver_data(struct virtio_device *vdev, void *data);
void *voidport_virtio_driver_data(struct virtio_device *vdev);
void voidport_virtio_del_vqs(struct virtio_device *vdev);
bool voidport_virtio_indirect(struct virtio_device *vdev);
struct workqueue_struct *voidport_virtio_alloc_workqueue(void);
void voidport_virtio_fs_tag(struct virtio_device *vdev, u8 *tag);
u32 voidport_virtio_fs_queues(struct virtio_device *vdev);
void voidport_sg_set_page(struct scatterlist *sg, struct page *page,
			  unsigned int len, unsigned int offset);
struct page *voidport_folio_page(struct folio *folio, unsigned long index);
void voidport_get_page(struct page *page);
void voidport_put_page(struct page *page);

#endif /* VOIDPORT_HELPERS_H */
