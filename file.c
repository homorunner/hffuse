/*
  HFFUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "hffuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/splice.h>

static int hffuse_send_open(struct hffuse_mount *fm, u64 nodeid,
			  unsigned int open_flags, int opcode,
			  struct hffuse_open_out *outargp)
{
	struct hffuse_open_in inarg;
	HFFUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = open_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	if (!fm->fc->atomic_o_trunc)
		inarg.flags &= ~O_TRUNC;

	if (fm->fc->handle_killpriv_v2 &&
	    (inarg.flags & O_TRUNC) && !capable(CAP_FSETID)) {
		inarg.open_flags |= HFFUSE_OPEN_KILL_SUIDGID;
	}

	args.opcode = opcode;
	args.nodeid = nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(*outargp);
	args.out_args[0].value = outargp;

	return hffuse_simple_request(fm, &args);
}

struct hffuse_release_args {
	struct hffuse_args args;
	struct hffuse_release_in inarg;
	struct inode *inode;
};

struct hffuse_file *hffuse_file_alloc(struct hffuse_mount *fm)
{
	struct hffuse_file *ff;

	ff = kzalloc(sizeof(struct hffuse_file), GFP_KERNEL_ACCOUNT);
	if (unlikely(!ff))
		return NULL;

	ff->fm = fm;
	ff->release_args = kzalloc(sizeof(*ff->release_args),
				   GFP_KERNEL_ACCOUNT);
	if (!ff->release_args) {
		kfree(ff);
		return NULL;
	}

	INIT_LIST_HEAD(&ff->write_entry);
	mutex_init(&ff->readdir.lock);
	refcount_set(&ff->count, 1);
	RB_CLEAR_NODE(&ff->polled_node);
	init_waitqueue_head(&ff->poll_wait);

	ff->kh = atomic64_inc_return(&fm->fc->khctr);

	return ff;
}

void hffuse_file_free(struct hffuse_file *ff)
{
	kfree(ff->release_args);
	mutex_destroy(&ff->readdir.lock);
	kfree(ff);
}

static struct hffuse_file *hffuse_file_get(struct hffuse_file *ff)
{
	refcount_inc(&ff->count);
	return ff;
}

static void hffuse_release_end(struct hffuse_mount *fm, struct hffuse_args *args,
			     int error)
{
	struct hffuse_release_args *ra = container_of(args, typeof(*ra), args);

	iput(ra->inode);
	kfree(ra);
}

static void hffuse_file_put(struct hffuse_file *ff, bool sync, bool isdir)
{
	if (refcount_dec_and_test(&ff->count)) {
		struct hffuse_args *args = &ff->release_args->args;

		if (isdir ? ff->fm->fc->no_opendir : ff->fm->fc->no_open) {
			/* Do nothing when client does not implement 'open' */
			hffuse_release_end(ff->fm, args, 0);
		} else if (sync) {
			hffuse_simple_request(ff->fm, args);
			hffuse_release_end(ff->fm, args, 0);
		} else {
			args->end = hffuse_release_end;
			if (hffuse_simple_background(ff->fm, args,
						   GFP_KERNEL | __GFP_NOFAIL))
				hffuse_release_end(ff->fm, args, -ENOTCONN);
		}
		kfree(ff);
	}
}

struct hffuse_file *hffuse_file_open(struct hffuse_mount *fm, u64 nodeid,
				 unsigned int open_flags, bool isdir)
{
	struct hffuse_conn *fc = fm->fc;
	struct hffuse_file *ff;
	int opcode = isdir ? HFFUSE_OPENDIR : HFFUSE_OPEN;

	ff = hffuse_file_alloc(fm);
	if (!ff)
		return ERR_PTR(-ENOMEM);

	ff->fh = 0;
	/* Default for no-open */
	ff->open_flags = FOPEN_KEEP_CACHE | (isdir ? FOPEN_CACHE_DIR : 0);
	if (isdir ? !fc->no_opendir : !fc->no_open) {
		struct hffuse_open_out outarg;
		int err;

		err = hffuse_send_open(fm, nodeid, open_flags, opcode, &outarg);
		if (!err) {
			ff->fh = outarg.fh;
			ff->open_flags = outarg.open_flags;

		} else if (err != -ENOSYS) {
			hffuse_file_free(ff);
			return ERR_PTR(err);
		} else {
			if (isdir)
				fc->no_opendir = 1;
			else
				fc->no_open = 1;
		}
	}

	if (isdir)
		ff->open_flags &= ~FOPEN_DIRECT_IO;

	ff->nodeid = nodeid;

	return ff;
}

int hffuse_do_open(struct hffuse_mount *fm, u64 nodeid, struct file *file,
		 bool isdir)
{
	struct hffuse_file *ff = hffuse_file_open(fm, nodeid, file->f_flags, isdir);

	if (!IS_ERR(ff))
		file->private_data = ff;

	return PTR_ERR_OR_ZERO(ff);
}
EXPORT_SYMBOL_GPL(hffuse_do_open);

static void hffuse_link_write_file(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_file *ff = file->private_data;
	/*
	 * file may be written through mmap, so chain it onto the
	 * inodes's write_file list
	 */
	spin_lock(&fi->lock);
	if (list_empty(&ff->write_entry))
		list_add(&ff->write_entry, &fi->write_files);
	spin_unlock(&fi->lock);
}

void hffuse_finish_open(struct inode *inode, struct file *file)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_conn *fc = get_hffuse_conn(inode);

	if (ff->open_flags & FOPEN_STREAM)
		stream_open(inode, file);
	else if (ff->open_flags & FOPEN_NONSEEKABLE)
		nonseekable_open(inode, file);

	if (fc->atomic_o_trunc && (file->f_flags & O_TRUNC)) {
		struct hffuse_inode *fi = get_hffuse_inode(inode);

		spin_lock(&fi->lock);
		fi->attr_version = atomic64_inc_return(&fc->attr_version);
		i_size_write(inode, 0);
		spin_unlock(&fi->lock);
		file_update_time(file);
		hffuse_invalidate_attr_mask(inode, HFFUSE_STATX_MODSIZE);
	}
	if ((file->f_mode & FMODE_WRITE) && fc->writeback_cache)
		hffuse_link_write_file(file);
}

int hffuse_open_common(struct inode *inode, struct file *file, bool isdir)
{
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	struct hffuse_conn *fc = fm->fc;
	int err;
	bool is_wb_truncate = (file->f_flags & O_TRUNC) &&
			  fc->atomic_o_trunc &&
			  fc->writeback_cache;
	bool dax_truncate = (file->f_flags & O_TRUNC) &&
			  fc->atomic_o_trunc && HFFUSE_IS_DAX(inode);

	if (hffuse_is_bad(inode))
		return -EIO;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	if (is_wb_truncate || dax_truncate)
		inode_lock(inode);

	if (dax_truncate) {
		filemap_invalidate_lock(inode->i_mapping);
		err = hffuse_dax_break_layouts(inode, 0, 0);
		if (err)
			goto out_inode_unlock;
	}

	if (is_wb_truncate || dax_truncate)
		hffuse_set_nowrite(inode);

	err = hffuse_do_open(fm, get_node_id(inode), file, isdir);
	if (!err)
		hffuse_finish_open(inode, file);

	if (is_wb_truncate || dax_truncate)
		hffuse_release_nowrite(inode);
	if (!err) {
		struct hffuse_file *ff = file->private_data;

		if (fc->atomic_o_trunc && (file->f_flags & O_TRUNC))
			truncate_pagecache(inode, 0);
		else if (!(ff->open_flags & FOPEN_KEEP_CACHE))
			invalidate_inode_pages2(inode->i_mapping);
	}
	if (dax_truncate)
		filemap_invalidate_unlock(inode->i_mapping);
out_inode_unlock:
	if (is_wb_truncate || dax_truncate)
		inode_unlock(inode);

	return err;
}

static void hffuse_prepare_release(struct hffuse_inode *fi, struct hffuse_file *ff,
				 unsigned int flags, int opcode)
{
	struct hffuse_conn *fc = ff->fm->fc;
	struct hffuse_release_args *ra = ff->release_args;

	/* Inode is NULL on error path of hffuse_create_open() */
	if (likely(fi)) {
		spin_lock(&fi->lock);
		list_del(&ff->write_entry);
		spin_unlock(&fi->lock);
	}
	spin_lock(&fc->lock);
	if (!RB_EMPTY_NODE(&ff->polled_node))
		rb_erase(&ff->polled_node, &fc->polled_files);
	spin_unlock(&fc->lock);

	wake_up_interruptible_all(&ff->poll_wait);

	ra->inarg.fh = ff->fh;
	ra->inarg.flags = flags;
	ra->args.in_numargs = 1;
	ra->args.in_args[0].size = sizeof(struct hffuse_release_in);
	ra->args.in_args[0].value = &ra->inarg;
	ra->args.opcode = opcode;
	ra->args.nodeid = ff->nodeid;
	ra->args.force = true;
	ra->args.nocreds = true;
}

void hffuse_file_release(struct inode *inode, struct hffuse_file *ff,
		       unsigned int open_flags, fl_owner_t id, bool isdir)
{
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_release_args *ra = ff->release_args;
	int opcode = isdir ? HFFUSE_RELEASEDIR : HFFUSE_RELEASE;

	hffuse_prepare_release(fi, ff, open_flags, opcode);

	if (ff->flock) {
		ra->inarg.release_flags |= HFFUSE_RELEASE_FLOCK_UNLOCK;
		ra->inarg.lock_owner = hffuse_lock_owner_id(ff->fm->fc, id);
	}
	/* Hold inode until release is finished */
	ra->inode = igrab(inode);

	/*
	 * Normally this will send the RELEASE request, however if
	 * some asynchronous READ or WRITE requests are outstanding,
	 * the sending will be delayed.
	 *
	 * Make the release synchronous if this is a hffuseblk mount,
	 * synchronous RELEASE is allowed (and desirable) in this case
	 * because the server can be trusted not to screw up.
	 */
	hffuse_file_put(ff, ff->fm->fc->destroy, isdir);
}

void hffuse_release_common(struct file *file, bool isdir)
{
	hffuse_file_release(file_inode(file), file->private_data, file->f_flags,
			  (fl_owner_t) file, isdir);
}

static int hffuse_open(struct inode *inode, struct file *file)
{
	return hffuse_open_common(inode, file, false);
}

static int hffuse_release(struct inode *inode, struct file *file)
{
	struct hffuse_conn *fc = get_hffuse_conn(inode);

	/*
	 * Dirty pages might remain despite write_inode_now() call from
	 * hffuse_flush() due to writes racing with the close.
	 */
	if (fc->writeback_cache)
		write_inode_now(inode, 1);

	hffuse_release_common(file, false);

	/* return value is ignored by VFS */
	return 0;
}

void hffuse_sync_release(struct hffuse_inode *fi, struct hffuse_file *ff,
		       unsigned int flags)
{
	WARN_ON(refcount_read(&ff->count) > 1);
	hffuse_prepare_release(fi, ff, flags, HFFUSE_RELEASE);
	/*
	 * iput(NULL) is a no-op and since the refcount is 1 and everything's
	 * synchronous, we are fine with not doing igrab() here"
	 */
	hffuse_file_put(ff, true, false);
}
EXPORT_SYMBOL_GPL(hffuse_sync_release);

/*
 * Scramble the ID space with XTEA, so that the value of the files_struct
 * pointer is not exposed to userspace.
 */
u64 hffuse_lock_owner_id(struct hffuse_conn *fc, fl_owner_t id)
{
	u32 *k = fc->scramble_key;
	u64 v = (unsigned long) id;
	u32 v0 = v;
	u32 v1 = v >> 32;
	u32 sum = 0;
	int i;

	for (i = 0; i < 32; i++) {
		v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
		sum += 0x9E3779B9;
		v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
	}

	return (u64) v0 + ((u64) v1 << 32);
}

struct hffuse_writepage_args {
	struct hffuse_io_args ia;
	struct rb_node writepages_entry;
	struct list_head queue_entry;
	struct hffuse_writepage_args *next;
	struct inode *inode;
	struct hffuse_sync_bucket *bucket;
};

static struct hffuse_writepage_args *hffuse_find_writeback(struct hffuse_inode *fi,
					    pgoff_t idx_from, pgoff_t idx_to)
{
	struct rb_node *n;

	n = fi->writepages.rb_node;

	while (n) {
		struct hffuse_writepage_args *wpa;
		pgoff_t curr_index;

		wpa = rb_entry(n, struct hffuse_writepage_args, writepages_entry);
		WARN_ON(get_hffuse_inode(wpa->inode) != fi);
		curr_index = wpa->ia.write.in.offset >> PAGE_SHIFT;
		if (idx_from >= curr_index + wpa->ia.ap.num_pages)
			n = n->rb_right;
		else if (idx_to < curr_index)
			n = n->rb_left;
		else
			return wpa;
	}
	return NULL;
}

/*
 * Check if any page in a range is under writeback
 *
 * This is currently done by walking the list of writepage requests
 * for the inode, which can be pretty inefficient.
 */
static bool hffuse_range_is_writeback(struct inode *inode, pgoff_t idx_from,
				   pgoff_t idx_to)
{
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	bool found;

	spin_lock(&fi->lock);
	found = hffuse_find_writeback(fi, idx_from, idx_to);
	spin_unlock(&fi->lock);

	return found;
}

static inline bool hffuse_page_is_writeback(struct inode *inode, pgoff_t index)
{
	return hffuse_range_is_writeback(inode, index, index);
}

/*
 * Wait for page writeback to be completed.
 *
 * Since hffuse doesn't rely on the VM writeback tracking, this has to
 * use some other means.
 */
static void hffuse_wait_on_page_writeback(struct inode *inode, pgoff_t index)
{
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	wait_event(fi->page_waitq, !hffuse_page_is_writeback(inode, index));
}

/*
 * Wait for all pending writepages on the inode to finish.
 *
 * This is currently done by blocking further writes with HFFUSE_NOWRITE
 * and waiting for all sent writes to complete.
 *
 * This must be called under i_mutex, otherwise the HFFUSE_NOWRITE usage
 * could conflict with truncation.
 */
static void hffuse_sync_writes(struct inode *inode)
{
	hffuse_set_nowrite(inode);
	hffuse_release_nowrite(inode);
}

static int hffuse_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	struct hffuse_file *ff = file->private_data;
	struct hffuse_flush_in inarg;
	HFFUSE_ARGS(args);
	int err;

	if (hffuse_is_bad(inode))
		return -EIO;

	if (ff->open_flags & FOPEN_NOFLUSH && !fm->fc->writeback_cache)
		return 0;

	err = write_inode_now(inode, 1);
	if (err)
		return err;

	inode_lock(inode);
	hffuse_sync_writes(inode);
	inode_unlock(inode);

	err = filemap_check_errors(file->f_mapping);
	if (err)
		return err;

	err = 0;
	if (fm->fc->no_flush)
		goto inval_attr_out;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.lock_owner = hffuse_lock_owner_id(fm->fc, id);
	args.opcode = HFFUSE_FLUSH;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.force = true;

	err = hffuse_simple_request(fm, &args);
	if (err == -ENOSYS) {
		fm->fc->no_flush = 1;
		err = 0;
	}

inval_attr_out:
	/*
	 * In memory i_blocks is not maintained by hffuse, if writeback cache is
	 * enabled, i_blocks from cached attr may not be accurate.
	 */
	if (!err && fm->fc->writeback_cache)
		hffuse_invalidate_attr_mask(inode, STATX_BLOCKS);
	return err;
}

int hffuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int opcode)
{
	struct inode *inode = file->f_mapping->host;
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	struct hffuse_file *ff = file->private_data;
	HFFUSE_ARGS(args);
	struct hffuse_fsync_in inarg;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.fsync_flags = datasync ? HFFUSE_FSYNC_FDATASYNC : 0;
	args.opcode = opcode;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	return hffuse_simple_request(fm, &args);
}

static int hffuse_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	int err;

	if (hffuse_is_bad(inode))
		return -EIO;

	inode_lock(inode);

	/*
	 * Start writeback against all dirty pages of the inode, then
	 * wait for all outstanding writes, before sending the FSYNC
	 * request.
	 */
	err = file_write_and_wait_range(file, start, end);
	if (err)
		goto out;

	hffuse_sync_writes(inode);

	/*
	 * Due to implementation of hffuse writeback
	 * file_write_and_wait_range() does not catch errors.
	 * We have to do this directly after hffuse_sync_writes()
	 */
	err = file_check_and_advance_wb_err(file);
	if (err)
		goto out;

	err = sync_inode_metadata(inode, 1);
	if (err)
		goto out;

	if (fc->no_fsync)
		goto out;

	err = hffuse_fsync_common(file, start, end, datasync, HFFUSE_FSYNC);
	if (err == -ENOSYS) {
		fc->no_fsync = 1;
		err = 0;
	}
out:
	inode_unlock(inode);

	return err;
}

void hffuse_read_args_fill(struct hffuse_io_args *ia, struct file *file, loff_t pos,
			 size_t count, int opcode)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_args *args = &ia->ap.args;

	ia->read.in.fh = ff->fh;
	ia->read.in.offset = pos;
	ia->read.in.size = count;
	ia->read.in.flags = file->f_flags;
	args->opcode = opcode;
	args->nodeid = ff->nodeid;
	args->in_numargs = 1;
	args->in_args[0].size = sizeof(ia->read.in);
	args->in_args[0].value = &ia->read.in;
	args->out_argvar = true;
	args->out_numargs = 1;
	args->out_args[0].size = count;
}

static void hffuse_release_user_pages(struct hffuse_args_pages *ap, ssize_t nres,
				    bool should_dirty)
{
	unsigned int i;

	for (i = 0; i < ap->num_pages; i++) {
		if (should_dirty)
			set_page_dirty_lock(ap->pages[i]);
		put_page(ap->pages[i]);
	}

	if (nres > 0 && ap->args.invalidate_vmap)
		invalidate_kernel_vmap_range(ap->args.vmap_base, nres);
}

static void hffuse_io_release(struct kref *kref)
{
	kfree(container_of(kref, struct hffuse_io_priv, refcnt));
}

static ssize_t hffuse_get_res_by_io(struct hffuse_io_priv *io)
{
	if (io->err)
		return io->err;

	if (io->bytes >= 0 && io->write)
		return -EIO;

	return io->bytes < 0 ? io->size : io->bytes;
}

/*
 * In case of short read, the caller sets 'pos' to the position of
 * actual end of hffuse request in IO request. Otherwise, if bytes_requested
 * == bytes_transferred or rw == WRITE, the caller sets 'pos' to -1.
 *
 * An example:
 * User requested DIO read of 64K. It was split into two 32K hffuse requests,
 * both submitted asynchronously. The first of them was ACKed by userspace as
 * fully completed (req->out.args[0].size == 32K) resulting in pos == -1. The
 * second request was ACKed as short, e.g. only 1K was read, resulting in
 * pos == 33K.
 *
 * Thus, when all hffuse requests are completed, the minimal non-negative 'pos'
 * will be equal to the length of the longest contiguous fragment of
 * transferred data starting from the beginning of IO request.
 */
static void hffuse_aio_complete(struct hffuse_io_priv *io, int err, ssize_t pos)
{
	int left;

	spin_lock(&io->lock);
	if (err)
		io->err = io->err ? : err;
	else if (pos >= 0 && (io->bytes < 0 || pos < io->bytes))
		io->bytes = pos;

	left = --io->reqs;
	if (!left && io->blocking)
		complete(io->done);
	spin_unlock(&io->lock);

	if (!left && !io->blocking) {
		ssize_t res = hffuse_get_res_by_io(io);

		if (res >= 0) {
			struct inode *inode = file_inode(io->iocb->ki_filp);
			struct hffuse_conn *fc = get_hffuse_conn(inode);
			struct hffuse_inode *fi = get_hffuse_inode(inode);

			spin_lock(&fi->lock);
			fi->attr_version = atomic64_inc_return(&fc->attr_version);
			spin_unlock(&fi->lock);
		}

		io->iocb->ki_complete(io->iocb, res);
	}

	kref_put(&io->refcnt, hffuse_io_release);
}

static struct hffuse_io_args *hffuse_io_alloc(struct hffuse_io_priv *io,
					  unsigned int npages)
{
	struct hffuse_io_args *ia;

	ia = kzalloc(sizeof(*ia), GFP_KERNEL);
	if (ia) {
		ia->io = io;
		ia->ap.pages = hffuse_pages_alloc(npages, GFP_KERNEL,
						&ia->ap.descs);
		if (!ia->ap.pages) {
			kfree(ia);
			ia = NULL;
		}
	}
	return ia;
}

static void hffuse_io_free(struct hffuse_io_args *ia)
{
	kfree(ia->ap.pages);
	kfree(ia);
}

static void hffuse_aio_complete_req(struct hffuse_mount *fm, struct hffuse_args *args,
				  int err)
{
	struct hffuse_io_args *ia = container_of(args, typeof(*ia), ap.args);
	struct hffuse_io_priv *io = ia->io;
	ssize_t pos = -1;
	size_t nres;

	if (err) {
		/* Nothing */
	} else if (io->write) {
		if (ia->write.out.size > ia->write.in.size) {
			err = -EIO;
		} else {
			nres = ia->write.out.size;
			if (ia->write.in.size != ia->write.out.size)
				pos = ia->write.in.offset - io->offset +
				      ia->write.out.size;
		}
	} else {
		u32 outsize = args->out_args[0].size;

		nres = outsize;
		if (ia->read.in.size != outsize)
			pos = ia->read.in.offset - io->offset + outsize;
	}

	hffuse_release_user_pages(&ia->ap, err ?: nres, io->should_dirty);

	hffuse_aio_complete(io, err, pos);
	hffuse_io_free(ia);
}

static ssize_t hffuse_async_req_send(struct hffuse_mount *fm,
				   struct hffuse_io_args *ia, size_t num_bytes)
{
	ssize_t err;
	struct hffuse_io_priv *io = ia->io;

	spin_lock(&io->lock);
	kref_get(&io->refcnt);
	io->size += num_bytes;
	io->reqs++;
	spin_unlock(&io->lock);

	ia->ap.args.end = hffuse_aio_complete_req;
	ia->ap.args.may_block = io->should_dirty;
	err = hffuse_simple_background(fm, &ia->ap.args, GFP_KERNEL);
	if (err)
		hffuse_aio_complete_req(fm, &ia->ap.args, err);

	return num_bytes;
}

static ssize_t hffuse_send_read(struct hffuse_io_args *ia, loff_t pos, size_t count,
			      fl_owner_t owner)
{
	struct file *file = ia->io->iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct hffuse_mount *fm = ff->fm;

	hffuse_read_args_fill(ia, file, pos, count, HFFUSE_READ);
	if (owner != NULL) {
		ia->read.in.read_flags |= HFFUSE_READ_LOCKOWNER;
		ia->read.in.lock_owner = hffuse_lock_owner_id(fm->fc, owner);
	}

	if (ia->io->async)
		return hffuse_async_req_send(fm, ia, count);

	return hffuse_simple_request(fm, &ia->ap.args);
}

static void hffuse_read_update_size(struct inode *inode, loff_t size,
				  u64 attr_ver)
{
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	spin_lock(&fi->lock);
	if (attr_ver >= fi->attr_version && size < inode->i_size &&
	    !test_bit(HFFUSE_I_SIZE_UNSTABLE, &fi->state)) {
		fi->attr_version = atomic64_inc_return(&fc->attr_version);
		i_size_write(inode, size);
	}
	spin_unlock(&fi->lock);
}

static void hffuse_short_read(struct inode *inode, u64 attr_ver, size_t num_read,
			    struct hffuse_args_pages *ap)
{
	struct hffuse_conn *fc = get_hffuse_conn(inode);

	/*
	 * If writeback_cache is enabled, a short read means there's a hole in
	 * the file.  Some data after the hole is in page cache, but has not
	 * reached the client fs yet.  So the hole is not present there.
	 */
	if (!fc->writeback_cache) {
		loff_t pos = page_offset(ap->pages[0]) + num_read;
		hffuse_read_update_size(inode, pos, attr_ver);
	}
}

static int hffuse_do_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	loff_t pos = page_offset(page);
	struct hffuse_page_desc desc = { .length = PAGE_SIZE };
	struct hffuse_io_args ia = {
		.ap.args.page_zeroing = true,
		.ap.args.out_pages = true,
		.ap.num_pages = 1,
		.ap.pages = &page,
		.ap.descs = &desc,
	};
	ssize_t res;
	u64 attr_ver;

	/*
	 * Page writeback can extend beyond the lifetime of the
	 * page-cache page, so make sure we read a properly synced
	 * page.
	 */
	hffuse_wait_on_page_writeback(inode, page->index);

	attr_ver = hffuse_get_attr_version(fm->fc);

	/* Don't overflow end offset */
	if (pos + (desc.length - 1) == LLONG_MAX)
		desc.length--;

	hffuse_read_args_fill(&ia, file, pos, desc.length, HFFUSE_READ);
	res = hffuse_simple_request(fm, &ia.ap.args);
	if (res < 0)
		return res;
	/*
	 * Short read means EOF.  If file size is larger, truncate it
	 */
	if (res < desc.length)
		hffuse_short_read(inode, attr_ver, res, &ia.ap);

	SetPageUptodate(page);

	return 0;
}

static int hffuse_read_folio(struct file *file, struct folio *folio)
{
	struct page *page = &folio->page;
	struct inode *inode = page->mapping->host;
	int err;

	err = -EIO;
	if (hffuse_is_bad(inode))
		goto out;

	err = hffuse_do_readpage(file, page);
	hffuse_invalidate_atime(inode);
 out:
	unlock_page(page);
	return err;
}

static void hffuse_readpages_end(struct hffuse_mount *fm, struct hffuse_args *args,
			       int err)
{
	int i;
	struct hffuse_io_args *ia = container_of(args, typeof(*ia), ap.args);
	struct hffuse_args_pages *ap = &ia->ap;
	size_t count = ia->read.in.size;
	size_t num_read = args->out_args[0].size;
	struct address_space *mapping = NULL;

	for (i = 0; mapping == NULL && i < ap->num_pages; i++)
		mapping = ap->pages[i]->mapping;

	if (mapping) {
		struct inode *inode = mapping->host;

		/*
		 * Short read means EOF. If file size is larger, truncate it
		 */
		if (!err && num_read < count)
			hffuse_short_read(inode, ia->read.attr_ver, num_read, ap);

		hffuse_invalidate_atime(inode);
	}

	for (i = 0; i < ap->num_pages; i++) {
		struct page *page = ap->pages[i];

		if (!err)
			SetPageUptodate(page);
		else
			SetPageError(page);
		unlock_page(page);
		put_page(page);
	}
	if (ia->ff)
		hffuse_file_put(ia->ff, false, false);

	hffuse_io_free(ia);
}

static void hffuse_send_readpages(struct hffuse_io_args *ia, struct file *file)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_mount *fm = ff->fm;
	struct hffuse_args_pages *ap = &ia->ap;
	loff_t pos = page_offset(ap->pages[0]);
	size_t count = ap->num_pages << PAGE_SHIFT;
	ssize_t res;
	int err;

	ap->args.out_pages = true;
	ap->args.page_zeroing = true;
	ap->args.page_replace = true;

	/* Don't overflow end offset */
	if (pos + (count - 1) == LLONG_MAX) {
		count--;
		ap->descs[ap->num_pages - 1].length--;
	}
	WARN_ON((loff_t) (pos + count) < 0);

	hffuse_read_args_fill(ia, file, pos, count, HFFUSE_READ);
	ia->read.attr_ver = hffuse_get_attr_version(fm->fc);
	if (fm->fc->async_read) {
		ia->ff = hffuse_file_get(ff);
		ap->args.end = hffuse_readpages_end;
		err = hffuse_simple_background(fm, &ap->args, GFP_KERNEL);
		if (!err)
			return;
	} else {
		res = hffuse_simple_request(fm, &ap->args);
		err = res < 0 ? res : 0;
	}
	hffuse_readpages_end(fm, &ap->args, err);
}

static void hffuse_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	unsigned int i, max_pages, nr_pages = 0;

	if (hffuse_is_bad(inode))
		return;

	max_pages = min_t(unsigned int, fc->max_pages,
			fc->max_read / PAGE_SIZE);

	for (;;) {
		struct hffuse_io_args *ia;
		struct hffuse_args_pages *ap;

		if (fc->num_background >= fc->congestion_threshold &&
		    rac->ra->async_size >= readahead_count(rac))
			/*
			 * Congested and only async pages left, so skip the
			 * rest.
			 */
			break;

		nr_pages = readahead_count(rac) - nr_pages;
		if (nr_pages > max_pages)
			nr_pages = max_pages;
		if (nr_pages == 0)
			break;
		ia = hffuse_io_alloc(NULL, nr_pages);
		if (!ia)
			return;
		ap = &ia->ap;
		nr_pages = __readahead_batch(rac, ap->pages, nr_pages);
		for (i = 0; i < nr_pages; i++) {
			hffuse_wait_on_page_writeback(inode,
						    readahead_index(rac) + i);
			ap->descs[i].length = PAGE_SIZE;
		}
		ap->num_pages = nr_pages;
		hffuse_send_readpages(ia, rac->file);
	}
}

static ssize_t hffuse_cache_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);

	/*
	 * In auto invalidate mode, always update attributes on read.
	 * Otherwise, only update if we attempt to read past EOF (to ensure
	 * i_size is up to date).
	 */
	if (fc->auto_inval_data ||
	    (iocb->ki_pos + iov_iter_count(to) > i_size_read(inode))) {
		int err;
		err = hffuse_update_attributes(inode, iocb->ki_filp, STATX_SIZE);
		if (err)
			return err;
	}

	return generic_file_read_iter(iocb, to);
}

static void hffuse_write_args_fill(struct hffuse_io_args *ia, struct hffuse_file *ff,
				 loff_t pos, size_t count)
{
	struct hffuse_args *args = &ia->ap.args;

	ia->write.in.fh = ff->fh;
	ia->write.in.offset = pos;
	ia->write.in.size = count;
	args->opcode = HFFUSE_WRITE;
	args->nodeid = ff->nodeid;
	args->in_numargs = 2;
	if (ff->fm->fc->minor < 9)
		args->in_args[0].size = HFFUSE_COMPAT_WRITE_IN_SIZE;
	else
		args->in_args[0].size = sizeof(ia->write.in);
	args->in_args[0].value = &ia->write.in;
	args->in_args[1].size = count;
	args->out_numargs = 1;
	args->out_args[0].size = sizeof(ia->write.out);
	args->out_args[0].value = &ia->write.out;
}

static unsigned int hffuse_write_flags(struct kiocb *iocb)
{
	unsigned int flags = iocb->ki_filp->f_flags;

	if (iocb_is_dsync(iocb))
		flags |= O_DSYNC;
	if (iocb->ki_flags & IOCB_SYNC)
		flags |= O_SYNC;

	return flags;
}

static ssize_t hffuse_send_write(struct hffuse_io_args *ia, loff_t pos,
			       size_t count, fl_owner_t owner)
{
	struct kiocb *iocb = ia->io->iocb;
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct hffuse_mount *fm = ff->fm;
	struct hffuse_write_in *inarg = &ia->write.in;
	ssize_t err;

	hffuse_write_args_fill(ia, ff, pos, count);
	inarg->flags = hffuse_write_flags(iocb);
	if (owner != NULL) {
		inarg->write_flags |= HFFUSE_WRITE_LOCKOWNER;
		inarg->lock_owner = hffuse_lock_owner_id(fm->fc, owner);
	}

	if (ia->io->async)
		return hffuse_async_req_send(fm, ia, count);

	err = hffuse_simple_request(fm, &ia->ap.args);
	if (!err && ia->write.out.size > count)
		err = -EIO;

	return err ?: ia->write.out.size;
}

bool hffuse_write_update_attr(struct inode *inode, loff_t pos, ssize_t written)
{
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	bool ret = false;

	spin_lock(&fi->lock);
	fi->attr_version = atomic64_inc_return(&fc->attr_version);
	if (written > 0 && pos > inode->i_size) {
		i_size_write(inode, pos);
		ret = true;
	}
	spin_unlock(&fi->lock);

	hffuse_invalidate_attr_mask(inode, HFFUSE_STATX_MODSIZE);

	return ret;
}

static ssize_t hffuse_send_write_pages(struct hffuse_io_args *ia,
				     struct kiocb *iocb, struct inode *inode,
				     loff_t pos, size_t count)
{
	struct hffuse_args_pages *ap = &ia->ap;
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct hffuse_mount *fm = ff->fm;
	unsigned int offset, i;
	bool short_write;
	int err;

	for (i = 0; i < ap->num_pages; i++)
		hffuse_wait_on_page_writeback(inode, ap->pages[i]->index);

	hffuse_write_args_fill(ia, ff, pos, count);
	ia->write.in.flags = hffuse_write_flags(iocb);
	if (fm->fc->handle_killpriv_v2 && !capable(CAP_FSETID))
		ia->write.in.write_flags |= HFFUSE_WRITE_KILL_SUIDGID;

	err = hffuse_simple_request(fm, &ap->args);
	if (!err && ia->write.out.size > count)
		err = -EIO;

	short_write = ia->write.out.size < count;
	offset = ap->descs[0].offset;
	count = ia->write.out.size;
	for (i = 0; i < ap->num_pages; i++) {
		struct page *page = ap->pages[i];

		if (err) {
			ClearPageUptodate(page);
		} else {
			if (count >= PAGE_SIZE - offset)
				count -= PAGE_SIZE - offset;
			else {
				if (short_write)
					ClearPageUptodate(page);
				count = 0;
			}
			offset = 0;
		}
		if (ia->write.page_locked && (i == ap->num_pages - 1))
			unlock_page(page);
		put_page(page);
	}

	return err;
}

static ssize_t hffuse_fill_write_pages(struct hffuse_io_args *ia,
				     struct address_space *mapping,
				     struct iov_iter *ii, loff_t pos,
				     unsigned int max_pages)
{
	struct hffuse_args_pages *ap = &ia->ap;
	struct hffuse_conn *fc = get_hffuse_conn(mapping->host);
	unsigned offset = pos & (PAGE_SIZE - 1);
	size_t count = 0;
	int err;

	ap->args.in_pages = true;
	ap->descs[0].offset = offset;

	do {
		size_t tmp;
		struct page *page;
		pgoff_t index = pos >> PAGE_SHIFT;
		size_t bytes = min_t(size_t, PAGE_SIZE - offset,
				     iov_iter_count(ii));

		bytes = min_t(size_t, bytes, fc->max_write - count);

 again:
		err = -EFAULT;
		if (fault_in_iov_iter_readable(ii, bytes))
			break;

		err = -ENOMEM;
		page = grab_cache_page_write_begin(mapping, index);
		if (!page)
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		tmp = copy_page_from_iter_atomic(page, offset, bytes, ii);
		flush_dcache_page(page);

		if (!tmp) {
			unlock_page(page);
			put_page(page);
			goto again;
		}

		err = 0;
		ap->pages[ap->num_pages] = page;
		ap->descs[ap->num_pages].length = tmp;
		ap->num_pages++;

		count += tmp;
		pos += tmp;
		offset += tmp;
		if (offset == PAGE_SIZE)
			offset = 0;

		/* If we copied full page, mark it uptodate */
		if (tmp == PAGE_SIZE)
			SetPageUptodate(page);

		if (PageUptodate(page)) {
			unlock_page(page);
		} else {
			ia->write.page_locked = true;
			break;
		}
		if (!fc->big_writes)
			break;
	} while (iov_iter_count(ii) && count < fc->max_write &&
		 ap->num_pages < max_pages && offset == 0);

	return count > 0 ? count : err;
}

static inline unsigned int hffuse_wr_pages(loff_t pos, size_t len,
				     unsigned int max_pages)
{
	return min_t(unsigned int,
		     ((pos + len - 1) >> PAGE_SHIFT) -
		     (pos >> PAGE_SHIFT) + 1,
		     max_pages);
}

static ssize_t hffuse_perform_write(struct kiocb *iocb, struct iov_iter *ii)
{
	struct address_space *mapping = iocb->ki_filp->f_mapping;
	struct inode *inode = mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	loff_t pos = iocb->ki_pos;
	int err = 0;
	ssize_t res = 0;

	if (inode->i_size < pos + iov_iter_count(ii))
		set_bit(HFFUSE_I_SIZE_UNSTABLE, &fi->state);

	do {
		ssize_t count;
		struct hffuse_io_args ia = {};
		struct hffuse_args_pages *ap = &ia.ap;
		unsigned int nr_pages = hffuse_wr_pages(pos, iov_iter_count(ii),
						      fc->max_pages);

		ap->pages = hffuse_pages_alloc(nr_pages, GFP_KERNEL, &ap->descs);
		if (!ap->pages) {
			err = -ENOMEM;
			break;
		}

		count = hffuse_fill_write_pages(&ia, mapping, ii, pos, nr_pages);
		if (count <= 0) {
			err = count;
		} else {
			err = hffuse_send_write_pages(&ia, iocb, inode,
						    pos, count);
			if (!err) {
				size_t num_written = ia.write.out.size;

				res += num_written;
				pos += num_written;

				/* break out of the loop on short write */
				if (num_written != count)
					err = -EIO;
			}
		}
		kfree(ap->pages);
	} while (!err && iov_iter_count(ii));

	hffuse_write_update_attr(inode, pos, res);
	clear_bit(HFFUSE_I_SIZE_UNSTABLE, &fi->state);

	if (!res)
		return err;
	iocb->ki_pos += res;
	return res;
}

static ssize_t hffuse_cache_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	ssize_t written = 0;
	struct inode *inode = mapping->host;
	ssize_t err;
	struct hffuse_conn *fc = get_hffuse_conn(inode);

	if (fc->writeback_cache) {
		/* Update size (EOF optimization) and mode (SUID clearing) */
		err = hffuse_update_attributes(mapping->host, file,
					     STATX_SIZE | STATX_MODE);
		if (err)
			return err;

		if (fc->handle_killpriv_v2 &&
		    setattr_should_drop_suidgid(&nop_mnt_idmap,
						file_inode(file))) {
			goto writethrough;
		}

		return generic_file_write_iter(iocb, from);
	}

writethrough:
	inode_lock(inode);

	err = generic_write_checks(iocb, from);
	if (err <= 0)
		goto out;

	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		written = generic_file_direct_write(iocb, from);
		if (written < 0 || !iov_iter_count(from))
			goto out;
		written = direct_write_fallback(iocb, from, written,
				hffuse_perform_write(iocb, from));
	} else {
		written = hffuse_perform_write(iocb, from);
	}
out:
	inode_unlock(inode);
	if (written > 0)
		written = generic_write_sync(iocb, written);

	return written ? written : err;
}

static inline unsigned long hffuse_get_user_addr(const struct iov_iter *ii)
{
	return (unsigned long)iter_iov(ii)->iov_base + ii->iov_offset;
}

static inline size_t hffuse_get_frag_size(const struct iov_iter *ii,
					size_t max_size)
{
	return min(iov_iter_single_seg_count(ii), max_size);
}

static int hffuse_get_user_pages(struct hffuse_args_pages *ap, struct iov_iter *ii,
			       size_t *nbytesp, int write,
			       unsigned int max_pages,
			       bool use_pages_for_kvec_io)
{
	bool flush_or_invalidate = false;
	size_t nbytes = 0;  /* # bytes already packed in req */
	ssize_t ret = 0;

	/* Special case for kernel I/O: can copy directly into the buffer.
	 * However if the implementation of hffuse_conn requires pages instead of
	 * pointer (e.g., virtio-fs), use iov_iter_extract_pages() instead.
	 */
	if (iov_iter_is_kvec(ii)) {
		void *user_addr = (void *)hffuse_get_user_addr(ii);

		if (!use_pages_for_kvec_io) {
			size_t frag_size = hffuse_get_frag_size(ii, *nbytesp);

			if (write)
				ap->args.in_args[1].value = user_addr;
			else
				ap->args.out_args[0].value = user_addr;

			iov_iter_advance(ii, frag_size);
			*nbytesp = frag_size;
			return 0;
		}

		if (is_vmalloc_addr(user_addr)) {
			ap->args.vmap_base = user_addr;
			flush_or_invalidate = true;
		}
	}

	while (nbytes < *nbytesp && ap->num_pages < max_pages) {
		unsigned npages;
		size_t start;
		ret = iov_iter_get_pages2(ii, &ap->pages[ap->num_pages],
					*nbytesp - nbytes,
					max_pages - ap->num_pages,
					&start);
		if (ret < 0)
			break;

		nbytes += ret;

		ret += start;
		npages = DIV_ROUND_UP(ret, PAGE_SIZE);

		ap->descs[ap->num_pages].offset = start;
		hffuse_page_descs_length_init(ap->descs, ap->num_pages, npages);

		ap->num_pages += npages;
		ap->descs[ap->num_pages - 1].length -=
			(PAGE_SIZE - ret) & (PAGE_SIZE - 1);
	}

	if (write && flush_or_invalidate)
		flush_kernel_vmap_range(ap->args.vmap_base, nbytes);

	ap->args.invalidate_vmap = !write && flush_or_invalidate;
	ap->args.user_pages = true;
	if (write)
		ap->args.in_pages = true;
	else
		ap->args.out_pages = true;

	*nbytesp = nbytes;

	return ret < 0 ? ret : 0;
}

ssize_t hffuse_direct_io(struct hffuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags)
{
	int write = flags & HFFUSE_DIO_WRITE;
	int cuse = flags & HFFUSE_DIO_CUSE;
	struct file *file = io->iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct hffuse_file *ff = file->private_data;
	struct hffuse_conn *fc = ff->fm->fc;
	size_t nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	size_t count = iov_iter_count(iter);
	pgoff_t idx_from = pos >> PAGE_SHIFT;
	pgoff_t idx_to = (pos + count - 1) >> PAGE_SHIFT;
	ssize_t res = 0;
	int err = 0;
	struct hffuse_io_args *ia;
	unsigned int max_pages;
	bool fopen_direct_io = ff->open_flags & FOPEN_DIRECT_IO;

	max_pages = iov_iter_npages(iter, fc->max_pages);
	ia = hffuse_io_alloc(io, max_pages);
	if (!ia)
		return -ENOMEM;

	if (fopen_direct_io && fc->direct_io_allow_mmap) {
		res = filemap_write_and_wait_range(mapping, pos, pos + count - 1);
		if (res) {
			hffuse_io_free(ia);
			return res;
		}
	}
	if (!cuse && hffuse_range_is_writeback(inode, idx_from, idx_to)) {
		if (!write)
			inode_lock(inode);
		hffuse_sync_writes(inode);
		if (!write)
			inode_unlock(inode);
	}

	if (fopen_direct_io && write) {
		res = invalidate_inode_pages2_range(mapping, idx_from, idx_to);
		if (res) {
			hffuse_io_free(ia);
			return res;
		}
	}

	io->should_dirty = !write && user_backed_iter(iter);
	while (count) {
		ssize_t nres;
		fl_owner_t owner = current->files;
		size_t nbytes = min(count, nmax);

		err = hffuse_get_user_pages(&ia->ap, iter, &nbytes, write,
					  max_pages, fc->use_pages_for_kvec_io);
		if (err && !nbytes)
			break;

		if (write) {
			if (!capable(CAP_FSETID))
				ia->write.in.write_flags |= HFFUSE_WRITE_KILL_SUIDGID;

			nres = hffuse_send_write(ia, pos, nbytes, owner);
		} else {
			nres = hffuse_send_read(ia, pos, nbytes, owner);
		}

		if (!io->async || nres < 0) {
			hffuse_release_user_pages(&ia->ap, nres, io->should_dirty);
			hffuse_io_free(ia);
		}
		ia = NULL;
		if (nres < 0) {
			iov_iter_revert(iter, nbytes);
			err = nres;
			break;
		}
		WARN_ON(nres > nbytes);

		count -= nres;
		res += nres;
		pos += nres;
		if (nres != nbytes) {
			iov_iter_revert(iter, nbytes - nres);
			break;
		}
		if (count) {
			max_pages = iov_iter_npages(iter, fc->max_pages);
			ia = hffuse_io_alloc(io, max_pages);
			if (!ia)
				break;
		}
	}
	if (ia)
		hffuse_io_free(ia);
	if (res > 0)
		*ppos = pos;

	return res > 0 ? res : err;
}
EXPORT_SYMBOL_GPL(hffuse_direct_io);

static ssize_t __hffuse_direct_read(struct hffuse_io_priv *io,
				  struct iov_iter *iter,
				  loff_t *ppos)
{
	ssize_t res;
	struct inode *inode = file_inode(io->iocb->ki_filp);

	res = hffuse_direct_io(io, iter, ppos, 0);

	hffuse_invalidate_atime(inode);

	return res;
}

static ssize_t hffuse_direct_IO(struct kiocb *iocb, struct iov_iter *iter);

static ssize_t hffuse_direct_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t res;

	if (!is_sync_kiocb(iocb) && iocb->ki_flags & IOCB_DIRECT) {
		res = hffuse_direct_IO(iocb, to);
	} else {
		struct hffuse_io_priv io = HFFUSE_IO_PRIV_SYNC(iocb);

		res = __hffuse_direct_read(&io, to, &iocb->ki_pos);
	}

	return res;
}

static bool hffuse_direct_write_extending_i_size(struct kiocb *iocb,
					       struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	return iocb->ki_pos + iov_iter_count(iter) > i_size_read(inode);
}

static ssize_t hffuse_direct_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct hffuse_io_priv io = HFFUSE_IO_PRIV_SYNC(iocb);
	ssize_t res;
	bool exclusive_lock =
		!(ff->open_flags & FOPEN_PARALLEL_DIRECT_WRITES) ||
		get_hffuse_conn(inode)->direct_io_allow_mmap ||
		iocb->ki_flags & IOCB_APPEND ||
		hffuse_direct_write_extending_i_size(iocb, from);

	/*
	 * Take exclusive lock if
	 * - Parallel direct writes are disabled - a user space decision
	 * - Parallel direct writes are enabled and i_size is being extended.
	 * - Shared mmap on direct_io file is supported (HFFUSE_DIRECT_IO_ALLOW_MMAP).
	 *   This might not be needed at all, but needs further investigation.
	 */
	if (exclusive_lock)
		inode_lock(inode);
	else {
		inode_lock_shared(inode);

		/* A race with truncate might have come up as the decision for
		 * the lock type was done without holding the lock, check again.
		 */
		if (hffuse_direct_write_extending_i_size(iocb, from)) {
			inode_unlock_shared(inode);
			inode_lock(inode);
			exclusive_lock = true;
		}
	}

	res = generic_write_checks(iocb, from);
	if (res > 0) {
		if (!is_sync_kiocb(iocb) && iocb->ki_flags & IOCB_DIRECT) {
			res = hffuse_direct_IO(iocb, from);
		} else {
			res = hffuse_direct_io(&io, from, &iocb->ki_pos,
					     HFFUSE_DIO_WRITE);
			hffuse_write_update_attr(inode, iocb->ki_pos, res);
		}
	}
	if (exclusive_lock)
		inode_unlock(inode);
	else
		inode_unlock_shared(inode);

	return res;
}

static ssize_t hffuse_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);

	if (hffuse_is_bad(inode))
		return -EIO;

	if (HFFUSE_IS_DAX(inode))
		return hffuse_dax_read_iter(iocb, to);

	if (!(ff->open_flags & FOPEN_DIRECT_IO))
		return hffuse_cache_read_iter(iocb, to);
	else
		return hffuse_direct_read_iter(iocb, to);
}

static ssize_t hffuse_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);

	if (hffuse_is_bad(inode))
		return -EIO;

	if (HFFUSE_IS_DAX(inode))
		return hffuse_dax_write_iter(iocb, from);

	if (!(ff->open_flags & FOPEN_DIRECT_IO))
		return hffuse_cache_write_iter(iocb, from);
	else
		return hffuse_direct_write_iter(iocb, from);
}

static void hffuse_writepage_free(struct hffuse_writepage_args *wpa)
{
	struct hffuse_args_pages *ap = &wpa->ia.ap;
	int i;

	if (wpa->bucket)
		hffuse_sync_bucket_dec(wpa->bucket);

	for (i = 0; i < ap->num_pages; i++)
		__free_page(ap->pages[i]);

	if (wpa->ia.ff)
		hffuse_file_put(wpa->ia.ff, false, false);

	kfree(ap->pages);
	kfree(wpa);
}

static void hffuse_writepage_finish(struct hffuse_mount *fm,
				  struct hffuse_writepage_args *wpa)
{
	struct hffuse_args_pages *ap = &wpa->ia.ap;
	struct inode *inode = wpa->inode;
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	int i;

	for (i = 0; i < ap->num_pages; i++) {
		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
		dec_node_page_state(ap->pages[i], NR_WRITEBACK_TEMP);
		wb_writeout_inc(&bdi->wb);
	}
	wake_up(&fi->page_waitq);
}

/* Called under fi->lock, may release and reacquire it */
static void hffuse_send_writepage(struct hffuse_mount *fm,
				struct hffuse_writepage_args *wpa, loff_t size)
__releases(fi->lock)
__acquires(fi->lock)
{
	struct hffuse_writepage_args *aux, *next;
	struct hffuse_inode *fi = get_hffuse_inode(wpa->inode);
	struct hffuse_write_in *inarg = &wpa->ia.write.in;
	struct hffuse_args *args = &wpa->ia.ap.args;
	__u64 data_size = wpa->ia.ap.num_pages * PAGE_SIZE;
	int err;

	fi->writectr++;
	if (inarg->offset + data_size <= size) {
		inarg->size = data_size;
	} else if (inarg->offset < size) {
		inarg->size = size - inarg->offset;
	} else {
		/* Got truncated off completely */
		goto out_free;
	}

	args->in_args[1].size = inarg->size;
	args->force = true;
	args->nocreds = true;

	err = hffuse_simple_background(fm, args, GFP_ATOMIC);
	if (err == -ENOMEM) {
		spin_unlock(&fi->lock);
		err = hffuse_simple_background(fm, args, GFP_NOFS | __GFP_NOFAIL);
		spin_lock(&fi->lock);
	}

	/* Fails on broken connection only */
	if (unlikely(err))
		goto out_free;

	return;

 out_free:
	fi->writectr--;
	rb_erase(&wpa->writepages_entry, &fi->writepages);
	hffuse_writepage_finish(fm, wpa);
	spin_unlock(&fi->lock);

	/* After rb_erase() aux request list is private */
	for (aux = wpa->next; aux; aux = next) {
		struct backing_dev_info *bdi = inode_to_bdi(aux->inode);

		next = aux->next;
		aux->next = NULL;

		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
		dec_node_page_state(aux->ia.ap.pages[0], NR_WRITEBACK_TEMP);
		wb_writeout_inc(&bdi->wb);
		hffuse_writepage_free(aux);
	}

	hffuse_writepage_free(wpa);
	spin_lock(&fi->lock);
}

/*
 * If fi->writectr is positive (no truncate or fsync going on) send
 * all queued writepage requests.
 *
 * Called with fi->lock
 */
void hffuse_flush_writepages(struct inode *inode)
__releases(fi->lock)
__acquires(fi->lock)
{
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	loff_t crop = i_size_read(inode);
	struct hffuse_writepage_args *wpa;

	while (fi->writectr >= 0 && !list_empty(&fi->queued_writes)) {
		wpa = list_entry(fi->queued_writes.next,
				 struct hffuse_writepage_args, queue_entry);
		list_del_init(&wpa->queue_entry);
		hffuse_send_writepage(fm, wpa, crop);
	}
}

static struct hffuse_writepage_args *hffuse_insert_writeback(struct rb_root *root,
						struct hffuse_writepage_args *wpa)
{
	pgoff_t idx_from = wpa->ia.write.in.offset >> PAGE_SHIFT;
	pgoff_t idx_to = idx_from + wpa->ia.ap.num_pages - 1;
	struct rb_node **p = &root->rb_node;
	struct rb_node  *parent = NULL;

	WARN_ON(!wpa->ia.ap.num_pages);
	while (*p) {
		struct hffuse_writepage_args *curr;
		pgoff_t curr_index;

		parent = *p;
		curr = rb_entry(parent, struct hffuse_writepage_args,
				writepages_entry);
		WARN_ON(curr->inode != wpa->inode);
		curr_index = curr->ia.write.in.offset >> PAGE_SHIFT;

		if (idx_from >= curr_index + curr->ia.ap.num_pages)
			p = &(*p)->rb_right;
		else if (idx_to < curr_index)
			p = &(*p)->rb_left;
		else
			return curr;
	}

	rb_link_node(&wpa->writepages_entry, parent, p);
	rb_insert_color(&wpa->writepages_entry, root);
	return NULL;
}

static void tree_insert(struct rb_root *root, struct hffuse_writepage_args *wpa)
{
	WARN_ON(hffuse_insert_writeback(root, wpa));
}

static void hffuse_writepage_end(struct hffuse_mount *fm, struct hffuse_args *args,
			       int error)
{
	struct hffuse_writepage_args *wpa =
		container_of(args, typeof(*wpa), ia.ap.args);
	struct inode *inode = wpa->inode;
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_conn *fc = get_hffuse_conn(inode);

	mapping_set_error(inode->i_mapping, error);
	/*
	 * A writeback finished and this might have updated mtime/ctime on
	 * server making local mtime/ctime stale.  Hence invalidate attrs.
	 * Do this only if writeback_cache is not enabled.  If writeback_cache
	 * is enabled, we trust local ctime/mtime.
	 */
	if (!fc->writeback_cache)
		hffuse_invalidate_attr_mask(inode, HFFUSE_STATX_MODIFY);
	spin_lock(&fi->lock);
	rb_erase(&wpa->writepages_entry, &fi->writepages);
	while (wpa->next) {
		struct hffuse_mount *fm = get_hffuse_mount(inode);
		struct hffuse_write_in *inarg = &wpa->ia.write.in;
		struct hffuse_writepage_args *next = wpa->next;

		wpa->next = next->next;
		next->next = NULL;
		next->ia.ff = hffuse_file_get(wpa->ia.ff);
		tree_insert(&fi->writepages, next);

		/*
		 * Skip hffuse_flush_writepages() to make it easy to crop requests
		 * based on primary request size.
		 *
		 * 1st case (trivial): there are no concurrent activities using
		 * hffuse_set/release_nowrite.  Then we're on safe side because
		 * hffuse_flush_writepages() would call hffuse_send_writepage()
		 * anyway.
		 *
		 * 2nd case: someone called hffuse_set_nowrite and it is waiting
		 * now for completion of all in-flight requests.  This happens
		 * rarely and no more than once per page, so this should be
		 * okay.
		 *
		 * 3rd case: someone (e.g. hffuse_do_setattr()) is in the middle
		 * of hffuse_set_nowrite..hffuse_release_nowrite section.  The fact
		 * that hffuse_set_nowrite returned implies that all in-flight
		 * requests were completed along with all of their secondary
		 * requests.  Further primary requests are blocked by negative
		 * writectr.  Hence there cannot be any in-flight requests and
		 * no invocations of hffuse_writepage_end() while we're in
		 * hffuse_set_nowrite..hffuse_release_nowrite section.
		 */
		hffuse_send_writepage(fm, next, inarg->offset + inarg->size);
	}
	fi->writectr--;
	hffuse_writepage_finish(fm, wpa);
	spin_unlock(&fi->lock);
	hffuse_writepage_free(wpa);
}

static struct hffuse_file *__hffuse_write_file_get(struct hffuse_inode *fi)
{
	struct hffuse_file *ff;

	spin_lock(&fi->lock);
	ff = list_first_entry_or_null(&fi->write_files, struct hffuse_file,
				      write_entry);
	if (ff)
		hffuse_file_get(ff);
	spin_unlock(&fi->lock);

	return ff;
}

static struct hffuse_file *hffuse_write_file_get(struct hffuse_inode *fi)
{
	struct hffuse_file *ff = __hffuse_write_file_get(fi);
	WARN_ON(!ff);
	return ff;
}

int hffuse_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_file *ff;
	int err;

	/*
	 * Inode is always written before the last reference is dropped and
	 * hence this should not be reached from reclaim.
	 *
	 * Writing back the inode from reclaim can deadlock if the request
	 * processing itself needs an allocation.  Allocations triggering
	 * reclaim while serving a request can't be prevented, because it can
	 * involve any number of unrelated userspace processes.
	 */
	WARN_ON(wbc->for_reclaim);

	ff = __hffuse_write_file_get(fi);
	err = hffuse_flush_times(inode, ff);
	if (ff)
		hffuse_file_put(ff, false, false);

	return err;
}

static struct hffuse_writepage_args *hffuse_writepage_args_alloc(void)
{
	struct hffuse_writepage_args *wpa;
	struct hffuse_args_pages *ap;

	wpa = kzalloc(sizeof(*wpa), GFP_NOFS);
	if (wpa) {
		ap = &wpa->ia.ap;
		ap->num_pages = 0;
		ap->pages = hffuse_pages_alloc(1, GFP_NOFS, &ap->descs);
		if (!ap->pages) {
			kfree(wpa);
			wpa = NULL;
		}
	}
	return wpa;

}

static void hffuse_writepage_add_to_bucket(struct hffuse_conn *fc,
					 struct hffuse_writepage_args *wpa)
{
	if (!fc->sync_fs)
		return;

	rcu_read_lock();
	/* Prevent resurrection of dead bucket in unlikely race with syncfs */
	do {
		wpa->bucket = rcu_dereference(fc->curr_bucket);
	} while (unlikely(!atomic_inc_not_zero(&wpa->bucket->count)));
	rcu_read_unlock();
}

static int hffuse_writepage_locked(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_writepage_args *wpa;
	struct hffuse_args_pages *ap;
	struct page *tmp_page;
	int error = -ENOMEM;

	set_page_writeback(page);

	wpa = hffuse_writepage_args_alloc();
	if (!wpa)
		goto err;
	ap = &wpa->ia.ap;

	tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (!tmp_page)
		goto err_free;

	error = -EIO;
	wpa->ia.ff = hffuse_write_file_get(fi);
	if (!wpa->ia.ff)
		goto err_nofile;

	hffuse_writepage_add_to_bucket(fc, wpa);
	hffuse_write_args_fill(&wpa->ia, wpa->ia.ff, page_offset(page), 0);

	copy_highpage(tmp_page, page);
	wpa->ia.write.in.write_flags |= HFFUSE_WRITE_CACHE;
	wpa->next = NULL;
	ap->args.in_pages = true;
	ap->num_pages = 1;
	ap->pages[0] = tmp_page;
	ap->descs[0].offset = 0;
	ap->descs[0].length = PAGE_SIZE;
	ap->args.end = hffuse_writepage_end;
	wpa->inode = inode;

	inc_wb_stat(&inode_to_bdi(inode)->wb, WB_WRITEBACK);
	inc_node_page_state(tmp_page, NR_WRITEBACK_TEMP);

	spin_lock(&fi->lock);
	tree_insert(&fi->writepages, wpa);
	list_add_tail(&wpa->queue_entry, &fi->queued_writes);
	hffuse_flush_writepages(inode);
	spin_unlock(&fi->lock);

	end_page_writeback(page);

	return 0;

err_nofile:
	__free_page(tmp_page);
err_free:
	kfree(wpa);
err:
	mapping_set_error(page->mapping, error);
	end_page_writeback(page);
	return error;
}

static int hffuse_writepage(struct page *page, struct writeback_control *wbc)
{
	struct hffuse_conn *fc = get_hffuse_conn(page->mapping->host);
	int err;

	if (hffuse_page_is_writeback(page->mapping->host, page->index)) {
		/*
		 * ->writepages() should be called for sync() and friends.  We
		 * should only get here on direct reclaim and then we are
		 * allowed to skip a page which is already in flight
		 */
		WARN_ON(wbc->sync_mode == WB_SYNC_ALL);

		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return 0;
	}

	if (wbc->sync_mode == WB_SYNC_NONE &&
	    fc->num_background >= fc->congestion_threshold)
		return AOP_WRITEPAGE_ACTIVATE;

	err = hffuse_writepage_locked(page);
	unlock_page(page);

	return err;
}

struct hffuse_fill_wb_data {
	struct hffuse_writepage_args *wpa;
	struct hffuse_file *ff;
	struct inode *inode;
	struct page **orig_pages;
	unsigned int max_pages;
};

static bool hffuse_pages_realloc(struct hffuse_fill_wb_data *data)
{
	struct hffuse_args_pages *ap = &data->wpa->ia.ap;
	struct hffuse_conn *fc = get_hffuse_conn(data->inode);
	struct page **pages;
	struct hffuse_page_desc *descs;
	unsigned int npages = min_t(unsigned int,
				    max_t(unsigned int, data->max_pages * 2,
					  HFFUSE_DEFAULT_MAX_PAGES_PER_REQ),
				    fc->max_pages);
	WARN_ON(npages <= data->max_pages);

	pages = hffuse_pages_alloc(npages, GFP_NOFS, &descs);
	if (!pages)
		return false;

	memcpy(pages, ap->pages, sizeof(struct page *) * ap->num_pages);
	memcpy(descs, ap->descs, sizeof(struct hffuse_page_desc) * ap->num_pages);
	kfree(ap->pages);
	ap->pages = pages;
	ap->descs = descs;
	data->max_pages = npages;

	return true;
}

static void hffuse_writepages_send(struct hffuse_fill_wb_data *data)
{
	struct hffuse_writepage_args *wpa = data->wpa;
	struct inode *inode = data->inode;
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	int num_pages = wpa->ia.ap.num_pages;
	int i;

	wpa->ia.ff = hffuse_file_get(data->ff);
	spin_lock(&fi->lock);
	list_add_tail(&wpa->queue_entry, &fi->queued_writes);
	hffuse_flush_writepages(inode);
	spin_unlock(&fi->lock);

	for (i = 0; i < num_pages; i++)
		end_page_writeback(data->orig_pages[i]);
}

/*
 * Check under fi->lock if the page is under writeback, and insert it onto the
 * rb_tree if not. Otherwise iterate auxiliary write requests, to see if there's
 * one already added for a page at this offset.  If there's none, then insert
 * this new request onto the auxiliary list, otherwise reuse the existing one by
 * swapping the new temp page with the old one.
 */
static bool hffuse_writepage_add(struct hffuse_writepage_args *new_wpa,
			       struct page *page)
{
	struct hffuse_inode *fi = get_hffuse_inode(new_wpa->inode);
	struct hffuse_writepage_args *tmp;
	struct hffuse_writepage_args *old_wpa;
	struct hffuse_args_pages *new_ap = &new_wpa->ia.ap;

	WARN_ON(new_ap->num_pages != 0);
	new_ap->num_pages = 1;

	spin_lock(&fi->lock);
	old_wpa = hffuse_insert_writeback(&fi->writepages, new_wpa);
	if (!old_wpa) {
		spin_unlock(&fi->lock);
		return true;
	}

	for (tmp = old_wpa->next; tmp; tmp = tmp->next) {
		pgoff_t curr_index;

		WARN_ON(tmp->inode != new_wpa->inode);
		curr_index = tmp->ia.write.in.offset >> PAGE_SHIFT;
		if (curr_index == page->index) {
			WARN_ON(tmp->ia.ap.num_pages != 1);
			swap(tmp->ia.ap.pages[0], new_ap->pages[0]);
			break;
		}
	}

	if (!tmp) {
		new_wpa->next = old_wpa->next;
		old_wpa->next = new_wpa;
	}

	spin_unlock(&fi->lock);

	if (tmp) {
		struct backing_dev_info *bdi = inode_to_bdi(new_wpa->inode);

		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
		dec_node_page_state(new_ap->pages[0], NR_WRITEBACK_TEMP);
		wb_writeout_inc(&bdi->wb);
		hffuse_writepage_free(new_wpa);
	}

	return false;
}

static bool hffuse_writepage_need_send(struct hffuse_conn *fc, struct page *page,
				     struct hffuse_args_pages *ap,
				     struct hffuse_fill_wb_data *data)
{
	WARN_ON(!ap->num_pages);

	/*
	 * Being under writeback is unlikely but possible.  For example direct
	 * read to an mmaped hffuse file will set the page dirty twice; once when
	 * the pages are faulted with get_user_pages(), and then after the read
	 * completed.
	 */
	if (hffuse_page_is_writeback(data->inode, page->index))
		return true;

	/* Reached max pages */
	if (ap->num_pages == fc->max_pages)
		return true;

	/* Reached max write bytes */
	if ((ap->num_pages + 1) * PAGE_SIZE > fc->max_write)
		return true;

	/* Discontinuity */
	if (data->orig_pages[ap->num_pages - 1]->index + 1 != page->index)
		return true;

	/* Need to grow the pages array?  If so, did the expansion fail? */
	if (ap->num_pages == data->max_pages && !hffuse_pages_realloc(data))
		return true;

	return false;
}

static int hffuse_writepages_fill(struct folio *folio,
		struct writeback_control *wbc, void *_data)
{
	struct hffuse_fill_wb_data *data = _data;
	struct hffuse_writepage_args *wpa = data->wpa;
	struct hffuse_args_pages *ap = &wpa->ia.ap;
	struct inode *inode = data->inode;
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct page *tmp_page;
	int err;

	if (!data->ff) {
		err = -EIO;
		data->ff = hffuse_write_file_get(fi);
		if (!data->ff)
			goto out_unlock;
	}

	if (wpa && hffuse_writepage_need_send(fc, &folio->page, ap, data)) {
		hffuse_writepages_send(data);
		data->wpa = NULL;
	}

	err = -ENOMEM;
	tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (!tmp_page)
		goto out_unlock;

	/*
	 * The page must not be redirtied until the writeout is completed
	 * (i.e. userspace has sent a reply to the write request).  Otherwise
	 * there could be more than one temporary page instance for each real
	 * page.
	 *
	 * This is ensured by holding the page lock in page_mkwrite() while
	 * checking hffuse_page_is_writeback().  We already hold the page lock
	 * since clear_page_dirty_for_io() and keep it held until we add the
	 * request to the fi->writepages list and increment ap->num_pages.
	 * After this hffuse_page_is_writeback() will indicate that the page is
	 * under writeback, so we can release the page lock.
	 */
	if (data->wpa == NULL) {
		err = -ENOMEM;
		wpa = hffuse_writepage_args_alloc();
		if (!wpa) {
			__free_page(tmp_page);
			goto out_unlock;
		}
		hffuse_writepage_add_to_bucket(fc, wpa);

		data->max_pages = 1;

		ap = &wpa->ia.ap;
		hffuse_write_args_fill(&wpa->ia, data->ff, folio_pos(folio), 0);
		wpa->ia.write.in.write_flags |= HFFUSE_WRITE_CACHE;
		wpa->next = NULL;
		ap->args.in_pages = true;
		ap->args.end = hffuse_writepage_end;
		ap->num_pages = 0;
		wpa->inode = inode;
	}
	folio_start_writeback(folio);

	copy_highpage(tmp_page, &folio->page);
	ap->pages[ap->num_pages] = tmp_page;
	ap->descs[ap->num_pages].offset = 0;
	ap->descs[ap->num_pages].length = PAGE_SIZE;
	data->orig_pages[ap->num_pages] = &folio->page;

	inc_wb_stat(&inode_to_bdi(inode)->wb, WB_WRITEBACK);
	inc_node_page_state(tmp_page, NR_WRITEBACK_TEMP);

	err = 0;
	if (data->wpa) {
		/*
		 * Protected by fi->lock against concurrent access by
		 * hffuse_page_is_writeback().
		 */
		spin_lock(&fi->lock);
		ap->num_pages++;
		spin_unlock(&fi->lock);
	} else if (hffuse_writepage_add(wpa, &folio->page)) {
		data->wpa = wpa;
	} else {
		folio_end_writeback(folio);
	}
out_unlock:
	folio_unlock(folio);

	return err;
}

static int hffuse_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_fill_wb_data data;
	int err;

	err = -EIO;
	if (hffuse_is_bad(inode))
		goto out;

	if (wbc->sync_mode == WB_SYNC_NONE &&
	    fc->num_background >= fc->congestion_threshold)
		return 0;

	data.inode = inode;
	data.wpa = NULL;
	data.ff = NULL;

	err = -ENOMEM;
	data.orig_pages = kcalloc(fc->max_pages,
				  sizeof(struct page *),
				  GFP_NOFS);
	if (!data.orig_pages)
		goto out;

	err = write_cache_pages(mapping, wbc, hffuse_writepages_fill, &data);
	if (data.wpa) {
		WARN_ON(!data.wpa->ia.ap.num_pages);
		hffuse_writepages_send(&data);
	}
	if (data.ff)
		hffuse_file_put(data.ff, false, false);

	kfree(data.orig_pages);
out:
	return err;
}

/*
 * It's worthy to make sure that space is reserved on disk for the write,
 * but how to implement it without killing performance need more thinking.
 */
static int hffuse_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_SHIFT;
	struct hffuse_conn *fc = get_hffuse_conn(file_inode(file));
	struct page *page;
	loff_t fsize;
	int err = -ENOMEM;

	WARN_ON(!fc->writeback_cache);

	page = grab_cache_page_write_begin(mapping, index);
	if (!page)
		goto error;

	hffuse_wait_on_page_writeback(mapping->host, page->index);

	if (PageUptodate(page) || len == PAGE_SIZE)
		goto success;
	/*
	 * Check if the start this page comes after the end of file, in which
	 * case the readpage can be optimized away.
	 */
	fsize = i_size_read(mapping->host);
	if (fsize <= (pos & PAGE_MASK)) {
		size_t off = pos & ~PAGE_MASK;
		if (off)
			zero_user_segment(page, 0, off);
		goto success;
	}
	err = hffuse_do_readpage(file, page);
	if (err)
		goto cleanup;
success:
	*pagep = page;
	return 0;

cleanup:
	unlock_page(page);
	put_page(page);
error:
	return err;
}

static int hffuse_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied,
		struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;

	/* Haven't copied anything?  Skip zeroing, size extending, dirtying. */
	if (!copied)
		goto unlock;

	pos += copied;
	if (!PageUptodate(page)) {
		/* Zero any unwritten bytes at the end of the page */
		size_t endoff = pos & ~PAGE_MASK;
		if (endoff)
			zero_user_segment(page, endoff, PAGE_SIZE);
		SetPageUptodate(page);
	}

	if (pos > inode->i_size)
		i_size_write(inode, pos);

	set_page_dirty(page);

unlock:
	unlock_page(page);
	put_page(page);

	return copied;
}

static int hffuse_launder_folio(struct folio *folio)
{
	int err = 0;
	if (folio_clear_dirty_for_io(folio)) {
		struct inode *inode = folio->mapping->host;

		/* Serialize with pending writeback for the same page */
		hffuse_wait_on_page_writeback(inode, folio->index);
		err = hffuse_writepage_locked(&folio->page);
		if (!err)
			hffuse_wait_on_page_writeback(inode, folio->index);
	}
	return err;
}

/*
 * Write back dirty data/metadata now (there may not be any suitable
 * open files later for data)
 */
static void hffuse_vma_close(struct vm_area_struct *vma)
{
	int err;

	err = write_inode_now(vma->vm_file->f_mapping->host, 1);
	mapping_set_error(vma->vm_file->f_mapping, err);
}

/*
 * Wait for writeback against this page to complete before allowing it
 * to be marked dirty again, and hence written back again, possibly
 * before the previous writepage completed.
 *
 * Block here, instead of in ->writepage(), so that the userspace fs
 * can only block processes actually operating on the filesystem.
 *
 * Otherwise unprivileged userspace fs would be able to block
 * unrelated:
 *
 * - page migration
 * - sync(2)
 * - try_to_free_pages() with order > PAGE_ALLOC_COSTLY_ORDER
 */
static vm_fault_t hffuse_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vmf->vma->vm_file);

	file_update_time(vmf->vma->vm_file);
	lock_page(page);
	if (page->mapping != inode->i_mapping) {
		unlock_page(page);
		return VM_FAULT_NOPAGE;
	}

	hffuse_wait_on_page_writeback(inode, page->index);
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct hffuse_file_vm_ops = {
	.close		= hffuse_vma_close,
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= hffuse_page_mkwrite,
};

static int hffuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_conn *fc = ff->fm->fc;

	/* DAX mmap is superior to direct_io mmap */
	if (HFFUSE_IS_DAX(file_inode(file)))
		return hffuse_dax_mmap(file, vma);

	if (ff->open_flags & FOPEN_DIRECT_IO) {
		/*
		 * Can't provide the coherency needed for MAP_SHARED
		 * if HFFUSE_DIRECT_IO_ALLOW_MMAP isn't set.
		 */
		if ((vma->vm_flags & VM_MAYSHARE) && !fc->direct_io_allow_mmap)
			return -ENODEV;

		invalidate_inode_pages2(file->f_mapping);

		if (!(vma->vm_flags & VM_MAYSHARE)) {
			/* MAP_PRIVATE */
			return generic_file_mmap(file, vma);
		}
	}

	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		hffuse_link_write_file(file);

	file_accessed(file);
	vma->vm_ops = &hffuse_file_vm_ops;
	return 0;
}

static int convert_hffuse_file_lock(struct hffuse_conn *fc,
				  const struct hffuse_file_lock *ffl,
				  struct file_lock *fl)
{
	switch (ffl->type) {
	case F_UNLCK:
		break;

	case F_RDLCK:
	case F_WRLCK:
		if (ffl->start > OFFSET_MAX || ffl->end > OFFSET_MAX ||
		    ffl->end < ffl->start)
			return -EIO;

		fl->fl_start = ffl->start;
		fl->fl_end = ffl->end;

		/*
		 * Convert pid into init's pid namespace.  The locks API will
		 * translate it into the caller's pid namespace.
		 */
		rcu_read_lock();
		fl->fl_pid = pid_nr_ns(find_pid_ns(ffl->pid, fc->pid_ns), &init_pid_ns);
		rcu_read_unlock();
		break;

	default:
		return -EIO;
	}
	fl->fl_type = ffl->type;
	return 0;
}

static void hffuse_lk_fill(struct hffuse_args *args, struct file *file,
			 const struct file_lock *fl, int opcode, pid_t pid,
			 int flock, struct hffuse_lk_in *inarg)
{
	struct inode *inode = file_inode(file);
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_file *ff = file->private_data;

	memset(inarg, 0, sizeof(*inarg));
	inarg->fh = ff->fh;
	inarg->owner = hffuse_lock_owner_id(fc, fl->fl_owner);
	inarg->lk.start = fl->fl_start;
	inarg->lk.end = fl->fl_end;
	inarg->lk.type = fl->fl_type;
	inarg->lk.pid = pid;
	if (flock)
		inarg->lk_flags |= HFFUSE_LK_FLOCK;
	args->opcode = opcode;
	args->nodeid = get_node_id(inode);
	args->in_numargs = 1;
	args->in_args[0].size = sizeof(*inarg);
	args->in_args[0].value = inarg;
}

static int hffuse_getlk(struct file *file, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	HFFUSE_ARGS(args);
	struct hffuse_lk_in inarg;
	struct hffuse_lk_out outarg;
	int err;

	hffuse_lk_fill(&args, file, fl, HFFUSE_GETLK, 0, 0, &inarg);
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;
	err = hffuse_simple_request(fm, &args);
	if (!err)
		err = convert_hffuse_file_lock(fm->fc, &outarg.lk, fl);

	return err;
}

static int hffuse_setlk(struct file *file, struct file_lock *fl, int flock)
{
	struct inode *inode = file_inode(file);
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	HFFUSE_ARGS(args);
	struct hffuse_lk_in inarg;
	int opcode = (fl->fl_flags & FL_SLEEP) ? HFFUSE_SETLKW : HFFUSE_SETLK;
	struct pid *pid = fl->fl_type != F_UNLCK ? task_tgid(current) : NULL;
	pid_t pid_nr = pid_nr_ns(pid, fm->fc->pid_ns);
	int err;

	if (fl->fl_lmops && fl->fl_lmops->lm_grant) {
		/* NLM needs asynchronous locks, which we don't support yet */
		return -ENOLCK;
	}

	/* Unlock on close is handled by the flush method */
	if ((fl->fl_flags & FL_CLOSE_POSIX) == FL_CLOSE_POSIX)
		return 0;

	hffuse_lk_fill(&args, file, fl, opcode, pid_nr, flock, &inarg);
	err = hffuse_simple_request(fm, &args);

	/* locking is restartable */
	if (err == -EINTR)
		err = -ERESTARTSYS;

	return err;
}

static int hffuse_file_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	int err;

	if (cmd == F_CANCELLK) {
		err = 0;
	} else if (cmd == F_GETLK) {
		if (fc->no_lock) {
			posix_test_lock(file, fl);
			err = 0;
		} else
			err = hffuse_getlk(file, fl);
	} else {
		if (fc->no_lock)
			err = posix_lock_file(file, fl, NULL);
		else
			err = hffuse_setlk(file, fl, 0);
	}
	return err;
}

static int hffuse_file_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	int err;

	if (fc->no_flock) {
		err = locks_lock_file_wait(file, fl);
	} else {
		struct hffuse_file *ff = file->private_data;

		/* emulate flock with POSIX locks */
		ff->flock = true;
		err = hffuse_setlk(file, fl, 1);
	}

	return err;
}

static sector_t hffuse_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	HFFUSE_ARGS(args);
	struct hffuse_bmap_in inarg;
	struct hffuse_bmap_out outarg;
	int err;

	if (!inode->i_sb->s_bdev || fm->fc->no_bmap)
		return 0;

	memset(&inarg, 0, sizeof(inarg));
	inarg.block = block;
	inarg.blocksize = inode->i_sb->s_blocksize;
	args.opcode = HFFUSE_BMAP;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;
	err = hffuse_simple_request(fm, &args);
	if (err == -ENOSYS)
		fm->fc->no_bmap = 1;

	return err ? 0 : outarg.block;
}

static loff_t hffuse_lseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	struct hffuse_file *ff = file->private_data;
	HFFUSE_ARGS(args);
	struct hffuse_lseek_in inarg = {
		.fh = ff->fh,
		.offset = offset,
		.whence = whence
	};
	struct hffuse_lseek_out outarg;
	int err;

	if (fm->fc->no_lseek)
		goto fallback;

	args.opcode = HFFUSE_LSEEK;
	args.nodeid = ff->nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;
	err = hffuse_simple_request(fm, &args);
	if (err) {
		if (err == -ENOSYS) {
			fm->fc->no_lseek = 1;
			goto fallback;
		}
		return err;
	}

	return vfs_setpos(file, outarg.offset, inode->i_sb->s_maxbytes);

fallback:
	err = hffuse_update_attributes(inode, file, STATX_SIZE);
	if (!err)
		return generic_file_llseek(file, offset, whence);
	else
		return err;
}

static loff_t hffuse_file_llseek(struct file *file, loff_t offset, int whence)
{
	loff_t retval;
	struct inode *inode = file_inode(file);

	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
		 /* No i_mutex protection necessary for SEEK_CUR and SEEK_SET */
		retval = generic_file_llseek(file, offset, whence);
		break;
	case SEEK_END:
		inode_lock(inode);
		retval = hffuse_update_attributes(inode, file, STATX_SIZE);
		if (!retval)
			retval = generic_file_llseek(file, offset, whence);
		inode_unlock(inode);
		break;
	case SEEK_HOLE:
	case SEEK_DATA:
		inode_lock(inode);
		retval = hffuse_lseek(file, offset, whence);
		inode_unlock(inode);
		break;
	default:
		retval = -EINVAL;
	}

	return retval;
}

/*
 * All files which have been polled are linked to RB tree
 * hffuse_conn->polled_files which is indexed by kh.  Walk the tree and
 * find the matching one.
 */
static struct rb_node **hffuse_find_polled_node(struct hffuse_conn *fc, u64 kh,
					      struct rb_node **parent_out)
{
	struct rb_node **link = &fc->polled_files.rb_node;
	struct rb_node *last = NULL;

	while (*link) {
		struct hffuse_file *ff;

		last = *link;
		ff = rb_entry(last, struct hffuse_file, polled_node);

		if (kh < ff->kh)
			link = &last->rb_left;
		else if (kh > ff->kh)
			link = &last->rb_right;
		else
			return link;
	}

	if (parent_out)
		*parent_out = last;
	return link;
}

/*
 * The file is about to be polled.  Make sure it's on the polled_files
 * RB tree.  Note that files once added to the polled_files tree are
 * not removed before the file is released.  This is because a file
 * polled once is likely to be polled again.
 */
static void hffuse_register_polled_file(struct hffuse_conn *fc,
				      struct hffuse_file *ff)
{
	spin_lock(&fc->lock);
	if (RB_EMPTY_NODE(&ff->polled_node)) {
		struct rb_node **link, *parent;

		link = hffuse_find_polled_node(fc, ff->kh, &parent);
		BUG_ON(*link);
		rb_link_node(&ff->polled_node, parent, link);
		rb_insert_color(&ff->polled_node, &fc->polled_files);
	}
	spin_unlock(&fc->lock);
}

__poll_t hffuse_file_poll(struct file *file, poll_table *wait)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_mount *fm = ff->fm;
	struct hffuse_poll_in inarg = { .fh = ff->fh, .kh = ff->kh };
	struct hffuse_poll_out outarg;
	HFFUSE_ARGS(args);
	int err;

	if (fm->fc->no_poll)
		return DEFAULT_POLLMASK;

	poll_wait(file, &ff->poll_wait, wait);
	inarg.events = mangle_poll(poll_requested_events(wait));

	/*
	 * Ask for notification iff there's someone waiting for it.
	 * The client may ignore the flag and always notify.
	 */
	if (waitqueue_active(&ff->poll_wait)) {
		inarg.flags |= HFFUSE_POLL_SCHEDULE_NOTIFY;
		hffuse_register_polled_file(fm->fc, ff);
	}

	args.opcode = HFFUSE_POLL;
	args.nodeid = ff->nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;
	err = hffuse_simple_request(fm, &args);

	if (!err)
		return demangle_poll(outarg.revents);
	if (err == -ENOSYS) {
		fm->fc->no_poll = 1;
		return DEFAULT_POLLMASK;
	}
	return EPOLLERR;
}
EXPORT_SYMBOL_GPL(hffuse_file_poll);

/*
 * This is called from hffuse_handle_notify() on HFFUSE_NOTIFY_POLL and
 * wakes up the poll waiters.
 */
int hffuse_notify_poll_wakeup(struct hffuse_conn *fc,
			    struct hffuse_notify_poll_wakeup_out *outarg)
{
	u64 kh = outarg->kh;
	struct rb_node **link;

	spin_lock(&fc->lock);

	link = hffuse_find_polled_node(fc, kh, NULL);
	if (*link) {
		struct hffuse_file *ff;

		ff = rb_entry(*link, struct hffuse_file, polled_node);
		wake_up_interruptible_sync(&ff->poll_wait);
	}

	spin_unlock(&fc->lock);
	return 0;
}

static void hffuse_do_truncate(struct file *file)
{
	struct inode *inode = file->f_mapping->host;
	struct iattr attr;

	attr.ia_valid = ATTR_SIZE;
	attr.ia_size = i_size_read(inode);

	attr.ia_file = file;
	attr.ia_valid |= ATTR_FILE;

	hffuse_do_setattr(file_dentry(file), &attr, file);
}

static inline loff_t hffuse_round_up(struct hffuse_conn *fc, loff_t off)
{
	return round_up(off, fc->max_pages << PAGE_SHIFT);
}

static ssize_t
hffuse_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	ssize_t ret = 0;
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	loff_t pos = 0;
	struct inode *inode;
	loff_t i_size;
	size_t count = iov_iter_count(iter), shortened = 0;
	loff_t offset = iocb->ki_pos;
	struct hffuse_io_priv *io;

	pos = offset;
	inode = file->f_mapping->host;
	i_size = i_size_read(inode);

	if ((iov_iter_rw(iter) == READ) && (offset >= i_size))
		return 0;

	io = kmalloc(sizeof(struct hffuse_io_priv), GFP_KERNEL);
	if (!io)
		return -ENOMEM;
	spin_lock_init(&io->lock);
	kref_init(&io->refcnt);
	io->reqs = 1;
	io->bytes = -1;
	io->size = 0;
	io->offset = offset;
	io->write = (iov_iter_rw(iter) == WRITE);
	io->err = 0;
	/*
	 * By default, we want to optimize all I/Os with async request
	 * submission to the client filesystem if supported.
	 */
	io->async = ff->fm->fc->async_dio;
	io->iocb = iocb;
	io->blocking = is_sync_kiocb(iocb);

	/* optimization for short read */
	if (io->async && !io->write && offset + count > i_size) {
		iov_iter_truncate(iter, hffuse_round_up(ff->fm->fc, i_size - offset));
		shortened = count - iov_iter_count(iter);
		count -= shortened;
	}

	/*
	 * We cannot asynchronously extend the size of a file.
	 * In such case the aio will behave exactly like sync io.
	 */
	if ((offset + count > i_size) && io->write)
		io->blocking = true;

	if (io->async && io->blocking) {
		/*
		 * Additional reference to keep io around after
		 * calling hffuse_aio_complete()
		 */
		kref_get(&io->refcnt);
		io->done = &wait;
	}

	if (iov_iter_rw(iter) == WRITE) {
		ret = hffuse_direct_io(io, iter, &pos, HFFUSE_DIO_WRITE);
		hffuse_invalidate_attr_mask(inode, HFFUSE_STATX_MODSIZE);
	} else {
		ret = __hffuse_direct_read(io, iter, &pos);
	}
	iov_iter_reexpand(iter, iov_iter_count(iter) + shortened);

	if (io->async) {
		bool blocking = io->blocking;

		hffuse_aio_complete(io, ret < 0 ? ret : 0, -1);

		/* we have a non-extending, async request, so return */
		if (!blocking)
			return -EIOCBQUEUED;

		wait_for_completion(&wait);
		ret = hffuse_get_res_by_io(io);
	}

	kref_put(&io->refcnt, hffuse_io_release);

	if (iov_iter_rw(iter) == WRITE) {
		hffuse_write_update_attr(inode, pos, ret);
		/* For extending writes we already hold exclusive lock */
		if (ret < 0 && offset + count > i_size)
			hffuse_do_truncate(file);
	}

	return ret;
}

static int hffuse_writeback_range(struct inode *inode, loff_t start, loff_t end)
{
	int err = filemap_write_and_wait_range(inode->i_mapping, start, LLONG_MAX);

	if (!err)
		hffuse_sync_writes(inode);

	return err;
}

static long hffuse_file_fallocate(struct file *file, int mode, loff_t offset,
				loff_t length)
{
	struct hffuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_mount *fm = ff->fm;
	HFFUSE_ARGS(args);
	struct hffuse_fallocate_in inarg = {
		.fh = ff->fh,
		.offset = offset,
		.length = length,
		.mode = mode
	};
	int err;
	bool block_faults = HFFUSE_IS_DAX(inode) &&
		(!(mode & FALLOC_FL_KEEP_SIZE) ||
		 (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)));

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_ZERO_RANGE))
		return -EOPNOTSUPP;

	if (fm->fc->no_fallocate)
		return -EOPNOTSUPP;

	inode_lock(inode);
	if (block_faults) {
		filemap_invalidate_lock(inode->i_mapping);
		err = hffuse_dax_break_layouts(inode, 0, 0);
		if (err)
			goto out;
	}

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)) {
		loff_t endbyte = offset + length - 1;

		err = hffuse_writeback_range(inode, offset, endbyte);
		if (err)
			goto out;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    offset + length > i_size_read(inode)) {
		err = inode_newsize_ok(inode, offset + length);
		if (err)
			goto out;
	}

	err = file_modified(file);
	if (err)
		goto out;

	if (!(mode & FALLOC_FL_KEEP_SIZE))
		set_bit(HFFUSE_I_SIZE_UNSTABLE, &fi->state);

	args.opcode = HFFUSE_FALLOCATE;
	args.nodeid = ff->nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	err = hffuse_simple_request(fm, &args);
	if (err == -ENOSYS) {
		fm->fc->no_fallocate = 1;
		err = -EOPNOTSUPP;
	}
	if (err)
		goto out;

	/* we could have extended the file */
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		if (hffuse_write_update_attr(inode, offset + length, length))
			file_update_time(file);
	}

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE))
		truncate_pagecache_range(inode, offset, offset + length - 1);

	hffuse_invalidate_attr_mask(inode, HFFUSE_STATX_MODSIZE);

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE))
		clear_bit(HFFUSE_I_SIZE_UNSTABLE, &fi->state);

	if (block_faults)
		filemap_invalidate_unlock(inode->i_mapping);

	inode_unlock(inode);

	hffuse_flush_time_update(inode);

	return err;
}

static ssize_t __hffuse_copy_file_range(struct file *file_in, loff_t pos_in,
				      struct file *file_out, loff_t pos_out,
				      size_t len, unsigned int flags)
{
	struct hffuse_file *ff_in = file_in->private_data;
	struct hffuse_file *ff_out = file_out->private_data;
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	struct hffuse_inode *fi_out = get_hffuse_inode(inode_out);
	struct hffuse_mount *fm = ff_in->fm;
	struct hffuse_conn *fc = fm->fc;
	HFFUSE_ARGS(args);
	struct hffuse_copy_file_range_in inarg = {
		.fh_in = ff_in->fh,
		.off_in = pos_in,
		.nodeid_out = ff_out->nodeid,
		.fh_out = ff_out->fh,
		.off_out = pos_out,
		.len = len,
		.flags = flags
	};
	struct hffuse_write_out outarg;
	ssize_t err;
	/* mark unstable when write-back is not used, and file_out gets
	 * extended */
	bool is_unstable = (!fc->writeback_cache) &&
			   ((pos_out + len) > inode_out->i_size);

	if (fc->no_copy_file_range)
		return -EOPNOTSUPP;

	if (file_inode(file_in)->i_sb != file_inode(file_out)->i_sb)
		return -EXDEV;

	inode_lock(inode_in);
	err = hffuse_writeback_range(inode_in, pos_in, pos_in + len - 1);
	inode_unlock(inode_in);
	if (err)
		return err;

	inode_lock(inode_out);

	err = file_modified(file_out);
	if (err)
		goto out;

	/*
	 * Write out dirty pages in the destination file before sending the COPY
	 * request to userspace.  After the request is completed, truncate off
	 * pages (including partial ones) from the cache that have been copied,
	 * since these contain stale data at that point.
	 *
	 * This should be mostly correct, but if the COPY writes to partial
	 * pages (at the start or end) and the parts not covered by the COPY are
	 * written through a memory map after calling hffuse_writeback_range(),
	 * then these partial page modifications will be lost on truncation.
	 *
	 * It is unlikely that someone would rely on such mixed style
	 * modifications.  Yet this does give less guarantees than if the
	 * copying was performed with write(2).
	 *
	 * To fix this a mapping->invalidate_lock could be used to prevent new
	 * faults while the copy is ongoing.
	 */
	err = hffuse_writeback_range(inode_out, pos_out, pos_out + len - 1);
	if (err)
		goto out;

	if (is_unstable)
		set_bit(HFFUSE_I_SIZE_UNSTABLE, &fi_out->state);

	args.opcode = HFFUSE_COPY_FILE_RANGE;
	args.nodeid = ff_in->nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;
	err = hffuse_simple_request(fm, &args);
	if (err == -ENOSYS) {
		fc->no_copy_file_range = 1;
		err = -EOPNOTSUPP;
	}
	if (err)
		goto out;

	truncate_inode_pages_range(inode_out->i_mapping,
				   ALIGN_DOWN(pos_out, PAGE_SIZE),
				   ALIGN(pos_out + outarg.size, PAGE_SIZE) - 1);

	file_update_time(file_out);
	hffuse_write_update_attr(inode_out, pos_out + outarg.size, outarg.size);

	err = outarg.size;
out:
	if (is_unstable)
		clear_bit(HFFUSE_I_SIZE_UNSTABLE, &fi_out->state);

	inode_unlock(inode_out);
	file_accessed(file_in);

	hffuse_flush_time_update(inode_out);

	return err;
}

static ssize_t hffuse_copy_file_range(struct file *src_file, loff_t src_off,
				    struct file *dst_file, loff_t dst_off,
				    size_t len, unsigned int flags)
{
	ssize_t ret;

	ret = __hffuse_copy_file_range(src_file, src_off, dst_file, dst_off,
				     len, flags);

	if (ret == -EOPNOTSUPP || ret == -EXDEV)
		ret = splice_copy_file_range(src_file, src_off, dst_file,
					     dst_off, len);
	return ret;
}

static const struct file_operations hffuse_file_operations = {
	.llseek		= hffuse_file_llseek,
	.read_iter	= hffuse_file_read_iter,
	.write_iter	= hffuse_file_write_iter,
	.mmap		= hffuse_file_mmap,
	.open		= hffuse_open,
	.flush		= hffuse_flush,
	.release	= hffuse_release,
	.fsync		= hffuse_fsync,
	.lock		= hffuse_file_lock,
	.get_unmapped_area = thp_get_unmapped_area,
	.flock		= hffuse_file_flock,
	.splice_read	= filemap_splice_read,
	.splice_write	= iter_file_splice_write,
	.unlocked_ioctl	= hffuse_file_ioctl,
	.compat_ioctl	= hffuse_file_compat_ioctl,
	.poll		= hffuse_file_poll,
	.fallocate	= hffuse_file_fallocate,
	.copy_file_range = hffuse_copy_file_range,
};

static const struct address_space_operations hffuse_file_aops  = {
	.read_folio	= hffuse_read_folio,
	.readahead	= hffuse_readahead,
	.writepage	= hffuse_writepage,
	.writepages	= hffuse_writepages,
	.launder_folio	= hffuse_launder_folio,
	.dirty_folio	= filemap_dirty_folio,
	.bmap		= hffuse_bmap,
	.direct_IO	= hffuse_direct_IO,
	.write_begin	= hffuse_write_begin,
	.write_end	= hffuse_write_end,
};

void hffuse_init_file_inode(struct inode *inode, unsigned int flags)
{
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	inode->i_fop = &hffuse_file_operations;
	inode->i_data.a_ops = &hffuse_file_aops;

	INIT_LIST_HEAD(&fi->write_files);
	INIT_LIST_HEAD(&fi->queued_writes);
	fi->writectr = 0;
	init_waitqueue_head(&fi->page_waitq);
	fi->writepages = RB_ROOT;

	if (IS_ENABLED(CONFIG_HFFUSE_DAX))
		hffuse_dax_inode_init(inode, flags);
}
