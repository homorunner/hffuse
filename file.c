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
#include <linux/task_io_accounting_ops.h>
#include <linux/iomap.h>

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

struct hffuse_file *hffuse_file_alloc(struct hffuse_mount *fm, bool release)
{
	struct hffuse_file *ff;

	ff = kzalloc(sizeof(struct hffuse_file), GFP_KERNEL_ACCOUNT);
	if (unlikely(!ff))
		return NULL;

	ff->fm = fm;
	if (release) {
		ff->args = kzalloc(sizeof(*ff->args), GFP_KERNEL_ACCOUNT);
		if (!ff->args) {
			kfree(ff);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&ff->write_entry);
	refcount_set(&ff->count, 1);
	RB_CLEAR_NODE(&ff->polled_node);
	init_waitqueue_head(&ff->poll_wait);

	ff->kh = atomic64_inc_return(&fm->fc->khctr);

	return ff;
}

void hffuse_file_free(struct hffuse_file *ff)
{
	kfree(ff->args);
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

static void hffuse_file_put(struct hffuse_file *ff, bool sync)
{
	if (refcount_dec_and_test(&ff->count)) {
		struct hffuse_release_args *ra = &ff->args->release_args;
		struct hffuse_args *args = (ra ? &ra->args : NULL);

		if (ra && ra->inode)
			hffuse_file_io_release(ff, ra->inode);

		if (!args) {
			/* Do nothing when server does not implement 'open' */
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
	bool open = isdir ? !fc->no_opendir : !fc->no_open;

	ff = hffuse_file_alloc(fm, open);
	if (!ff)
		return ERR_PTR(-ENOMEM);

	ff->fh = 0;
	/* Default for no-open */
	ff->open_flags = FOPEN_KEEP_CACHE | (isdir ? FOPEN_CACHE_DIR : 0);
	if (open) {
		/* Store outarg for hffuse_finish_open() */
		struct hffuse_open_out *outargp = &ff->args->open_outarg;
		int err;

		err = hffuse_send_open(fm, nodeid, open_flags, opcode, outargp);
		if (!err) {
			ff->fh = outargp->fh;
			ff->open_flags = outargp->open_flags;
		} else if (err != -ENOSYS) {
			hffuse_file_free(ff);
			return ERR_PTR(err);
		} else {
			/* No release needed */
			kfree(ff->args);
			ff->args = NULL;
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

int hffuse_finish_open(struct inode *inode, struct file *file)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	int err;

	err = hffuse_file_io_open(file, inode);
	if (err)
		return err;

	if (ff->open_flags & FOPEN_STREAM)
		stream_open(inode, file);
	else if (ff->open_flags & FOPEN_NONSEEKABLE)
		nonseekable_open(inode, file);

	if ((file->f_mode & FMODE_WRITE) && fc->writeback_cache)
		hffuse_link_write_file(file);

	return 0;
}

static void hffuse_truncate_update_attr(struct inode *inode, struct file *file)
{
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	spin_lock(&fi->lock);
	fi->attr_version = atomic64_inc_return(&fc->attr_version);
	i_size_write(inode, 0);
	spin_unlock(&fi->lock);
	file_update_time(file);
	hffuse_invalidate_attr_mask(inode, HFFUSE_STATX_MODSIZE);
}

static int hffuse_open(struct inode *inode, struct file *file)
{
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_conn *fc = fm->fc;
	struct hffuse_file *ff;
	int err;
	bool is_truncate = (file->f_flags & O_TRUNC) && fc->atomic_o_trunc;
	bool is_wb_truncate = is_truncate && fc->writeback_cache;
	bool dax_truncate = is_truncate && HFFUSE_IS_DAX(inode);

	if (hffuse_is_bad(inode))
		return -EIO;

	err = generic_file_open(inode, file);
	if (err)
		return err;

	if (is_wb_truncate || dax_truncate)
		inode_lock(inode);

	if (dax_truncate) {
		filemap_invalidate_lock(inode->i_mapping);
		err = hffuse_dax_break_layouts(inode, 0, -1);
		if (err)
			goto out_inode_unlock;
	}

	if (is_wb_truncate || dax_truncate)
		hffuse_set_nowrite(inode);

	err = hffuse_do_open(fm, get_node_id(inode), file, false);
	if (!err) {
		ff = file->private_data;
		err = hffuse_finish_open(inode, file);
		if (err)
			hffuse_sync_release(fi, ff, file->f_flags);
		else if (is_truncate)
			hffuse_truncate_update_attr(inode, file);
	}

	if (is_wb_truncate || dax_truncate)
		hffuse_release_nowrite(inode);
	if (!err) {
		if (is_truncate)
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
				 unsigned int flags, int opcode, bool sync)
{
	struct hffuse_conn *fc = ff->fm->fc;
	struct hffuse_release_args *ra = &ff->args->release_args;

	if (hffuse_file_passthrough(ff))
		hffuse_passthrough_release(ff, hffuse_inode_backing(fi));

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

	if (!ra)
		return;

	/* ff->args was used for open outarg */
	memset(ff->args, 0, sizeof(*ff->args));
	ra->inarg.fh = ff->fh;
	ra->inarg.flags = flags;
	ra->args.in_numargs = 1;
	ra->args.in_args[0].size = sizeof(struct hffuse_release_in);
	ra->args.in_args[0].value = &ra->inarg;
	ra->args.opcode = opcode;
	ra->args.nodeid = ff->nodeid;
	ra->args.force = true;
	ra->args.nocreds = true;

	/*
	 * Hold inode until release is finished.
	 * From hffuse_sync_release() the refcount is 1 and everything's
	 * synchronous, so we are fine with not doing igrab() here.
	 */
	ra->inode = sync ? NULL : igrab(&fi->inode);
}

void hffuse_file_release(struct inode *inode, struct hffuse_file *ff,
		       unsigned int open_flags, fl_owner_t id, bool isdir)
{
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_release_args *ra = &ff->args->release_args;
	int opcode = isdir ? HFFUSE_RELEASEDIR : HFFUSE_RELEASE;

	hffuse_prepare_release(fi, ff, open_flags, opcode, false);

	if (ra && ff->flock) {
		ra->inarg.release_flags |= HFFUSE_RELEASE_FLOCK_UNLOCK;
		ra->inarg.lock_owner = hffuse_lock_owner_id(ff->fm->fc, id);
	}

	/*
	 * Normally this will send the RELEASE request, however if
	 * some asynchronous READ or WRITE requests are outstanding,
	 * the sending will be delayed.
	 *
	 * Make the release synchronous if this is a hffuseblk mount,
	 * synchronous RELEASE is allowed (and desirable) in this case
	 * because the server can be trusted not to screw up.
	 */
	hffuse_file_put(ff, ff->fm->fc->destroy);
}

void hffuse_release_common(struct file *file, bool isdir)
{
	hffuse_file_release(file_inode(file), file->private_data, file->f_flags,
			  (fl_owner_t) file, isdir);
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
	hffuse_prepare_release(fi, ff, flags, HFFUSE_RELEASE, true);
	hffuse_file_put(ff, true);
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
	struct list_head queue_entry;
	struct inode *inode;
	struct hffuse_sync_bucket *bucket;
};

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

	for (i = 0; i < ap->num_folios; i++) {
		if (should_dirty)
			folio_mark_dirty_lock(ap->folios[i]);
		if (ap->args.is_pinned)
			unpin_folio(ap->folios[i]);
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
						 unsigned int nfolios)
{
	struct hffuse_io_args *ia;

	ia = kzalloc(sizeof(*ia), GFP_KERNEL);
	if (ia) {
		ia->io = io;
		ia->ap.folios = hffuse_folios_alloc(nfolios, GFP_KERNEL,
						  &ia->ap.descs);
		if (!ia->ap.folios) {
			kfree(ia);
			ia = NULL;
		}
	}
	return ia;
}

static void hffuse_io_free(struct hffuse_io_args *ia)
{
	kfree(ia->ap.folios);
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
		loff_t pos = folio_pos(ap->folios[0]) + num_read;
		hffuse_read_update_size(inode, pos, attr_ver);
	}
}

static int hffuse_do_readfolio(struct file *file, struct folio *folio,
			     size_t off, size_t len)
{
	struct inode *inode = folio->mapping->host;
	struct hffuse_mount *fm = get_hffuse_mount(inode);
	loff_t pos = folio_pos(folio) + off;
	struct hffuse_folio_desc desc = {
		.offset = off,
		.length = len,
	};
	struct hffuse_io_args ia = {
		.ap.args.page_zeroing = true,
		.ap.args.out_pages = true,
		.ap.num_folios = 1,
		.ap.folios = &folio,
		.ap.descs = &desc,
	};
	ssize_t res;
	u64 attr_ver;

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

	return 0;
}

static int hffuse_read_folio(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	int err;

	err = -EIO;
	if (hffuse_is_bad(inode))
		goto out;

	err = hffuse_do_readfolio(file, folio, 0, folio_size(folio));
	if (!err)
		folio_mark_uptodate(folio);

	hffuse_invalidate_atime(inode);
 out:
	folio_unlock(folio);
	return err;
}

static int hffuse_iomap_read_folio_range(const struct iomap_iter *iter,
				       struct folio *folio, loff_t pos,
				       size_t len)
{
	struct file *file = iter->private;
	size_t off = offset_in_folio(folio, pos);

	return hffuse_do_readfolio(file, folio, off, len);
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

	for (i = 0; mapping == NULL && i < ap->num_folios; i++)
		mapping = ap->folios[i]->mapping;

	if (mapping) {
		struct inode *inode = mapping->host;

		/*
		 * Short read means EOF. If file size is larger, truncate it
		 */
		if (!err && num_read < count)
			hffuse_short_read(inode, ia->read.attr_ver, num_read, ap);

		hffuse_invalidate_atime(inode);
	}

	for (i = 0; i < ap->num_folios; i++) {
		folio_end_read(ap->folios[i], !err);
		folio_put(ap->folios[i]);
	}
	if (ia->ff)
		hffuse_file_put(ia->ff, false);

	hffuse_io_free(ia);
}

static void hffuse_send_readpages(struct hffuse_io_args *ia, struct file *file,
				unsigned int count)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_mount *fm = ff->fm;
	struct hffuse_args_pages *ap = &ia->ap;
	loff_t pos = folio_pos(ap->folios[0]);
	ssize_t res;
	int err;

	ap->args.out_pages = true;
	ap->args.page_zeroing = true;
	ap->args.page_replace = true;

	/* Don't overflow end offset */
	if (pos + (count - 1) == LLONG_MAX) {
		count--;
		ap->descs[ap->num_folios - 1].length--;
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
	unsigned int max_pages, nr_pages;
	struct folio *folio = NULL;

	if (hffuse_is_bad(inode))
		return;

	max_pages = min_t(unsigned int, fc->max_pages,
			fc->max_read / PAGE_SIZE);

	/*
	 * This is only accurate the first time through, since readahead_folio()
	 * doesn't update readahead_count() from the previous folio until the
	 * next call.  Grab nr_pages here so we know how many pages we're going
	 * to have to process.  This means that we will exit here with
	 * readahead_count() == folio_nr_pages(last_folio), but we will have
	 * consumed all of the folios, and read_pages() will call
	 * readahead_folio() again which will clean up the rac.
	 */
	nr_pages = readahead_count(rac);

	while (nr_pages) {
		struct hffuse_io_args *ia;
		struct hffuse_args_pages *ap;
		unsigned cur_pages = min(max_pages, nr_pages);
		unsigned int pages = 0;

		if (fc->num_background >= fc->congestion_threshold &&
		    rac->ra->async_size >= readahead_count(rac))
			/*
			 * Congested and only async pages left, so skip the
			 * rest.
			 */
			break;

		ia = hffuse_io_alloc(NULL, cur_pages);
		if (!ia)
			break;
		ap = &ia->ap;

		while (pages < cur_pages) {
			unsigned int folio_pages;

			/*
			 * This returns a folio with a ref held on it.
			 * The ref needs to be held until the request is
			 * completed, since the splice case (see
			 * hffuse_try_move_page()) drops the ref after it's
			 * replaced in the page cache.
			 */
			if (!folio)
				folio =  __readahead_folio(rac);

			folio_pages = folio_nr_pages(folio);
			if (folio_pages > cur_pages - pages) {
				/*
				 * Large folios belonging to hffuse will never
				 * have more pages than max_pages.
				 */
				WARN_ON(!pages);
				break;
			}

			ap->folios[ap->num_folios] = folio;
			ap->descs[ap->num_folios].length = folio_size(folio);
			ap->num_folios++;
			pages += folio_pages;
			folio = NULL;
		}
		hffuse_send_readpages(ia, rac->file, pages << PAGE_SHIFT);
		nr_pages -= pages;
	}
	if (folio) {
		folio_end_read(folio, false);
		folio_put(folio);
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

	for (i = 0; i < ap->num_folios; i++)
		folio_wait_writeback(ap->folios[i]);

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
	for (i = 0; i < ap->num_folios; i++) {
		struct folio *folio = ap->folios[i];

		if (err) {
			folio_clear_uptodate(folio);
		} else {
			if (count >= folio_size(folio) - offset)
				count -= folio_size(folio) - offset;
			else {
				if (short_write)
					folio_clear_uptodate(folio);
				count = 0;
			}
			offset = 0;
		}
		if (ia->write.folio_locked && (i == ap->num_folios - 1))
			folio_unlock(folio);
		folio_put(folio);
	}

	return err;
}

static ssize_t hffuse_fill_write_pages(struct hffuse_io_args *ia,
				     struct address_space *mapping,
				     struct iov_iter *ii, loff_t pos,
				     unsigned int max_folios)
{
	struct hffuse_args_pages *ap = &ia->ap;
	struct hffuse_conn *fc = get_hffuse_conn(mapping->host);
	unsigned offset = pos & (PAGE_SIZE - 1);
	size_t count = 0;
	unsigned int num;
	int err = 0;

	num = min(iov_iter_count(ii), fc->max_write);

	ap->args.in_pages = true;
	ap->descs[0].offset = offset;

	while (num && ap->num_folios < max_folios) {
		size_t tmp;
		struct folio *folio;
		pgoff_t index = pos >> PAGE_SHIFT;
		unsigned int bytes;
		unsigned int folio_offset;

 again:
		folio = __filemap_get_folio(mapping, index, FGP_WRITEBEGIN,
					    mapping_gfp_mask(mapping));
		if (IS_ERR(folio)) {
			err = PTR_ERR(folio);
			break;
		}

		if (mapping_writably_mapped(mapping))
			flush_dcache_folio(folio);

		folio_offset = ((index - folio->index) << PAGE_SHIFT) + offset;
		bytes = min(folio_size(folio) - folio_offset, num);

		tmp = copy_folio_from_iter_atomic(folio, folio_offset, bytes, ii);
		flush_dcache_folio(folio);

		if (!tmp) {
			folio_unlock(folio);
			folio_put(folio);

			/*
			 * Ensure forward progress by faulting in
			 * while not holding the folio lock:
			 */
			if (fault_in_iov_iter_readable(ii, bytes)) {
				err = -EFAULT;
				break;
			}

			goto again;
		}

		ap->folios[ap->num_folios] = folio;
		ap->descs[ap->num_folios].offset = folio_offset;
		ap->descs[ap->num_folios].length = tmp;
		ap->num_folios++;

		count += tmp;
		pos += tmp;
		num -= tmp;
		offset += tmp;
		if (offset == folio_size(folio))
			offset = 0;

		/* If we copied full folio, mark it uptodate */
		if (tmp == folio_size(folio))
			folio_mark_uptodate(folio);

		if (folio_test_uptodate(folio)) {
			folio_unlock(folio);
		} else {
			ia->write.folio_locked = true;
			break;
		}
		if (!fc->big_writes || offset != 0)
			break;
	}

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

		ap->folios = hffuse_folios_alloc(nr_pages, GFP_KERNEL, &ap->descs);
		if (!ap->folios) {
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
		kfree(ap->folios);
	} while (!err && iov_iter_count(ii));

	hffuse_write_update_attr(inode, pos, res);
	clear_bit(HFFUSE_I_SIZE_UNSTABLE, &fi->state);

	if (!res)
		return err;
	iocb->ki_pos += res;
	return res;
}

static bool hffuse_io_past_eof(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	return iocb->ki_pos + iov_iter_count(iter) > i_size_read(inode);
}

/*
 * @return true if an exclusive lock for direct IO writes is needed
 */
static bool hffuse_dio_wr_exclusive_lock(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct inode *inode = file_inode(iocb->ki_filp);
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	/* Server side has to advise that it supports parallel dio writes. */
	if (!(ff->open_flags & FOPEN_PARALLEL_DIRECT_WRITES))
		return true;

	/*
	 * Append will need to know the eventual EOF - always needs an
	 * exclusive lock.
	 */
	if (iocb->ki_flags & IOCB_APPEND)
		return true;

	/* shared locks are not allowed with parallel page cache IO */
	if (test_bit(HFFUSE_I_CACHE_IO_MODE, &fi->state))
		return true;

	/* Parallel dio beyond EOF is not supported, at least for now. */
	if (hffuse_io_past_eof(iocb, from))
		return true;

	return false;
}

static void hffuse_dio_lock(struct kiocb *iocb, struct iov_iter *from,
			  bool *exclusive)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	*exclusive = hffuse_dio_wr_exclusive_lock(iocb, from);
	if (*exclusive) {
		inode_lock(inode);
	} else {
		inode_lock_shared(inode);
		/*
		 * New parallal dio allowed only if inode is not in caching
		 * mode and denies new opens in caching mode. This check
		 * should be performed only after taking shared inode lock.
		 * Previous past eof check was without inode lock and might
		 * have raced, so check it again.
		 */
		if (hffuse_io_past_eof(iocb, from) ||
		    hffuse_inode_uncached_io_start(fi, NULL) != 0) {
			inode_unlock_shared(inode);
			inode_lock(inode);
			*exclusive = true;
		}
	}
}

static void hffuse_dio_unlock(struct kiocb *iocb, bool exclusive)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	if (exclusive) {
		inode_unlock(inode);
	} else {
		/* Allow opens in caching mode after last parallel dio end */
		hffuse_inode_uncached_io_end(fi);
		inode_unlock_shared(inode);
	}
}

static const struct iomap_write_ops hffuse_iomap_write_ops = {
	.read_folio_range = hffuse_iomap_read_folio_range,
};

static int hffuse_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
			    unsigned int flags, struct iomap *iomap,
			    struct iomap *srcmap)
{
	iomap->type = IOMAP_MAPPED;
	iomap->length = length;
	iomap->offset = offset;
	return 0;
}

static const struct iomap_ops hffuse_iomap_ops = {
	.iomap_begin	= hffuse_iomap_begin,
};

static ssize_t hffuse_cache_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct mnt_idmap *idmap = file_mnt_idmap(file);
	struct address_space *mapping = file->f_mapping;
	ssize_t written = 0;
	struct inode *inode = mapping->host;
	ssize_t err, count;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	bool writeback = false;

	if (fc->writeback_cache) {
		/* Update size (EOF optimization) and mode (SUID clearing) */
		err = hffuse_update_attributes(mapping->host, file,
					     STATX_SIZE | STATX_MODE);
		if (err)
			return err;

		if (!fc->handle_killpriv_v2 ||
		    !setattr_should_drop_suidgid(idmap, file_inode(file)))
			writeback = true;
	}

	inode_lock(inode);

	err = count = generic_write_checks(iocb, from);
	if (err <= 0)
		goto out;

	task_io_account_write(count);

	err = kiocb_modified(iocb);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		written = generic_file_direct_write(iocb, from);
		if (written < 0 || !iov_iter_count(from))
			goto out;
		written = direct_write_fallback(iocb, from, written,
				hffuse_perform_write(iocb, from));
	} else if (writeback) {
		/*
		 * Use iomap so that we can do granular uptodate reads
		 * and granular dirty tracking for large folios.
		 */
		written = iomap_file_buffered_write(iocb, from,
						    &hffuse_iomap_ops,
						    &hffuse_iomap_write_ops,
						    file);
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
	unsigned int nr_pages = 0;
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

	/*
	 * Until there is support for iov_iter_extract_folios(), we have to
	 * manually extract pages using iov_iter_extract_pages() and then
	 * copy that to a folios array.
	 */
	struct page **pages = kzalloc(max_pages * sizeof(struct page *),
				      GFP_KERNEL);
	if (!pages) {
		ret = -ENOMEM;
		goto out;
	}

	while (nbytes < *nbytesp && nr_pages < max_pages) {
		unsigned nfolios, i;
		size_t start;

		ret = iov_iter_extract_pages(ii, &pages,
					     *nbytesp - nbytes,
					     max_pages - nr_pages,
					     0, &start);
		if (ret < 0)
			break;

		nbytes += ret;

		nfolios = DIV_ROUND_UP(ret + start, PAGE_SIZE);

		for (i = 0; i < nfolios; i++) {
			struct folio *folio = page_folio(pages[i]);
			unsigned int offset = start +
				(folio_page_idx(folio, pages[i]) << PAGE_SHIFT);
			unsigned int len = min_t(unsigned int, ret, PAGE_SIZE - start);

			ap->descs[ap->num_folios].offset = offset;
			ap->descs[ap->num_folios].length = len;
			ap->folios[ap->num_folios] = folio;
			start = 0;
			ret -= len;
			ap->num_folios++;
		}

		nr_pages += nfolios;
	}
	kfree(pages);

	if (write && flush_or_invalidate)
		flush_kernel_vmap_range(ap->args.vmap_base, nbytes);

	ap->args.invalidate_vmap = !write && flush_or_invalidate;
	ap->args.is_pinned = iov_iter_extract_will_pin(ii);
	ap->args.user_pages = true;
	if (write)
		ap->args.in_pages = true;
	else
		ap->args.out_pages = true;

out:
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
	if (!cuse && filemap_range_has_writeback(mapping, pos, (pos + count - 1))) {
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

	if (!is_sync_kiocb(iocb)) {
		res = hffuse_direct_IO(iocb, to);
	} else {
		struct hffuse_io_priv io = HFFUSE_IO_PRIV_SYNC(iocb);

		res = __hffuse_direct_read(&io, to, &iocb->ki_pos);
	}

	return res;
}

static ssize_t hffuse_direct_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t res;
	bool exclusive;

	hffuse_dio_lock(iocb, from, &exclusive);
	res = generic_write_checks(iocb, from);
	if (res > 0) {
		task_io_account_write(res);
		if (!is_sync_kiocb(iocb)) {
			res = hffuse_direct_IO(iocb, from);
		} else {
			struct hffuse_io_priv io = HFFUSE_IO_PRIV_SYNC(iocb);

			res = hffuse_direct_io(&io, from, &iocb->ki_pos,
					     HFFUSE_DIO_WRITE);
			hffuse_write_update_attr(inode, iocb->ki_pos, res);
		}
	}
	hffuse_dio_unlock(iocb, exclusive);

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

	/* FOPEN_DIRECT_IO overrides FOPEN_PASSTHROUGH */
	if (ff->open_flags & FOPEN_DIRECT_IO)
		return hffuse_direct_read_iter(iocb, to);
	else if (hffuse_file_passthrough(ff))
		return hffuse_passthrough_read_iter(iocb, to);
	else
		return hffuse_cache_read_iter(iocb, to);
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

	/* FOPEN_DIRECT_IO overrides FOPEN_PASSTHROUGH */
	if (ff->open_flags & FOPEN_DIRECT_IO)
		return hffuse_direct_write_iter(iocb, from);
	else if (hffuse_file_passthrough(ff))
		return hffuse_passthrough_write_iter(iocb, from);
	else
		return hffuse_cache_write_iter(iocb, from);
}

static ssize_t hffuse_splice_read(struct file *in, loff_t *ppos,
				struct pipe_inode_info *pipe, size_t len,
				unsigned int flags)
{
	struct hffuse_file *ff = in->private_data;

	/* FOPEN_DIRECT_IO overrides FOPEN_PASSTHROUGH */
	if (hffuse_file_passthrough(ff) && !(ff->open_flags & FOPEN_DIRECT_IO))
		return hffuse_passthrough_splice_read(in, ppos, pipe, len, flags);
	else
		return filemap_splice_read(in, ppos, pipe, len, flags);
}

static ssize_t hffuse_splice_write(struct pipe_inode_info *pipe, struct file *out,
				 loff_t *ppos, size_t len, unsigned int flags)
{
	struct hffuse_file *ff = out->private_data;

	/* FOPEN_DIRECT_IO overrides FOPEN_PASSTHROUGH */
	if (hffuse_file_passthrough(ff) && !(ff->open_flags & FOPEN_DIRECT_IO))
		return hffuse_passthrough_splice_write(pipe, out, ppos, len, flags);
	else
		return iter_file_splice_write(pipe, out, ppos, len, flags);
}

static void hffuse_writepage_free(struct hffuse_writepage_args *wpa)
{
	struct hffuse_args_pages *ap = &wpa->ia.ap;

	if (wpa->bucket)
		hffuse_sync_bucket_dec(wpa->bucket);

	hffuse_file_put(wpa->ia.ff, false);

	kfree(ap->folios);
	kfree(wpa);
}

static void hffuse_writepage_finish(struct hffuse_writepage_args *wpa)
{
	struct hffuse_args_pages *ap = &wpa->ia.ap;
	struct inode *inode = wpa->inode;
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	int i;

	for (i = 0; i < ap->num_folios; i++) {
		/*
		 * Benchmarks showed that ending writeback within the
		 * scope of the fi->lock alleviates xarray lock
		 * contention and noticeably improves performance.
		 */
		iomap_finish_folio_write(inode, ap->folios[i], 1);
		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
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
	struct hffuse_inode *fi = get_hffuse_inode(wpa->inode);
	struct hffuse_args_pages *ap = &wpa->ia.ap;
	struct hffuse_write_in *inarg = &wpa->ia.write.in;
	struct hffuse_args *args = &ap->args;
	__u64 data_size = 0;
	int err, i;

	for (i = 0; i < ap->num_folios; i++)
		data_size += ap->descs[i].length;

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
	hffuse_writepage_finish(wpa);
	spin_unlock(&fi->lock);
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
	fi->writectr--;
	hffuse_writepage_finish(wpa);
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

	ff = __hffuse_write_file_get(fi);
	err = hffuse_flush_times(inode, ff);
	if (ff)
		hffuse_file_put(ff, false);

	return err;
}

static struct hffuse_writepage_args *hffuse_writepage_args_alloc(void)
{
	struct hffuse_writepage_args *wpa;
	struct hffuse_args_pages *ap;

	wpa = kzalloc(sizeof(*wpa), GFP_NOFS);
	if (wpa) {
		ap = &wpa->ia.ap;
		ap->num_folios = 0;
		ap->folios = hffuse_folios_alloc(1, GFP_NOFS, &ap->descs);
		if (!ap->folios) {
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

static void hffuse_writepage_args_page_fill(struct hffuse_writepage_args *wpa, struct folio *folio,
					  uint32_t folio_index, loff_t offset, unsigned len)
{
	struct inode *inode = folio->mapping->host;
	struct hffuse_args_pages *ap = &wpa->ia.ap;

	ap->folios[folio_index] = folio;
	ap->descs[folio_index].offset = offset;
	ap->descs[folio_index].length = len;

	inc_wb_stat(&inode_to_bdi(inode)->wb, WB_WRITEBACK);
}

static struct hffuse_writepage_args *hffuse_writepage_args_setup(struct folio *folio,
							     size_t offset,
							     struct hffuse_file *ff)
{
	struct inode *inode = folio->mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_writepage_args *wpa;
	struct hffuse_args_pages *ap;

	wpa = hffuse_writepage_args_alloc();
	if (!wpa)
		return NULL;

	hffuse_writepage_add_to_bucket(fc, wpa);
	hffuse_write_args_fill(&wpa->ia, ff, folio_pos(folio) + offset, 0);
	wpa->ia.write.in.write_flags |= HFFUSE_WRITE_CACHE;
	wpa->inode = inode;
	wpa->ia.ff = ff;

	ap = &wpa->ia.ap;
	ap->args.in_pages = true;
	ap->args.end = hffuse_writepage_end;

	return wpa;
}

struct hffuse_fill_wb_data {
	struct hffuse_writepage_args *wpa;
	struct hffuse_file *ff;
	unsigned int max_folios;
	/*
	 * nr_bytes won't overflow since hffuse_writepage_need_send() caps
	 * wb requests to never exceed fc->max_pages (which has an upper bound
	 * of U16_MAX).
	 */
	unsigned int nr_bytes;
};

static bool hffuse_pages_realloc(struct hffuse_fill_wb_data *data,
			       unsigned int max_pages)
{
	struct hffuse_args_pages *ap = &data->wpa->ia.ap;
	struct folio **folios;
	struct hffuse_folio_desc *descs;
	unsigned int nfolios = min_t(unsigned int,
				     max_t(unsigned int, data->max_folios * 2,
					   HFFUSE_DEFAULT_MAX_PAGES_PER_REQ),
				    max_pages);
	WARN_ON(nfolios <= data->max_folios);

	folios = hffuse_folios_alloc(nfolios, GFP_NOFS, &descs);
	if (!folios)
		return false;

	memcpy(folios, ap->folios, sizeof(struct folio *) * ap->num_folios);
	memcpy(descs, ap->descs, sizeof(struct hffuse_folio_desc) * ap->num_folios);
	kfree(ap->folios);
	ap->folios = folios;
	ap->descs = descs;
	data->max_folios = nfolios;

	return true;
}

static void hffuse_writepages_send(struct inode *inode,
				 struct hffuse_fill_wb_data *data)
{
	struct hffuse_writepage_args *wpa = data->wpa;
	struct hffuse_inode *fi = get_hffuse_inode(inode);

	spin_lock(&fi->lock);
	list_add_tail(&wpa->queue_entry, &fi->queued_writes);
	hffuse_flush_writepages(inode);
	spin_unlock(&fi->lock);
}

static bool hffuse_writepage_need_send(struct hffuse_conn *fc, loff_t pos,
				     unsigned len, struct hffuse_args_pages *ap,
				     struct hffuse_fill_wb_data *data)
{
	struct folio *prev_folio;
	struct hffuse_folio_desc prev_desc;
	unsigned bytes = data->nr_bytes + len;
	loff_t prev_pos;

	WARN_ON(!ap->num_folios);

	/* Reached max pages */
	if ((bytes + PAGE_SIZE - 1) >> PAGE_SHIFT > fc->max_pages)
		return true;

	/* Reached max write bytes */
	if (bytes > fc->max_write)
		return true;

	/* Discontinuity */
	prev_folio = ap->folios[ap->num_folios - 1];
	prev_desc = ap->descs[ap->num_folios - 1];
	prev_pos = folio_pos(prev_folio) + prev_desc.offset + prev_desc.length;
	if (prev_pos != pos)
		return true;

	/* Need to grow the pages array?  If so, did the expansion fail? */
	if (ap->num_folios == data->max_folios &&
	    !hffuse_pages_realloc(data, fc->max_pages))
		return true;

	return false;
}

static ssize_t hffuse_iomap_writeback_range(struct iomap_writepage_ctx *wpc,
					  struct folio *folio, u64 pos,
					  unsigned len, u64 end_pos)
{
	struct hffuse_fill_wb_data *data = wpc->wb_ctx;
	struct hffuse_writepage_args *wpa = data->wpa;
	struct hffuse_args_pages *ap = &wpa->ia.ap;
	struct inode *inode = wpc->inode;
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	loff_t offset = offset_in_folio(folio, pos);

	WARN_ON_ONCE(!data);

	if (!data->ff) {
		data->ff = hffuse_write_file_get(fi);
		if (!data->ff)
			return -EIO;
	}

	if (wpa && hffuse_writepage_need_send(fc, pos, len, ap, data)) {
		hffuse_writepages_send(inode, data);
		data->wpa = NULL;
		data->nr_bytes = 0;
	}

	if (data->wpa == NULL) {
		wpa = hffuse_writepage_args_setup(folio, offset, data->ff);
		if (!wpa)
			return -ENOMEM;
		hffuse_file_get(wpa->ia.ff);
		data->max_folios = 1;
		ap = &wpa->ia.ap;
	}

	iomap_start_folio_write(inode, folio, 1);
	hffuse_writepage_args_page_fill(wpa, folio, ap->num_folios,
				      offset, len);
	data->nr_bytes += len;

	ap->num_folios++;
	if (!data->wpa)
		data->wpa = wpa;

	return len;
}

static int hffuse_iomap_writeback_submit(struct iomap_writepage_ctx *wpc,
				       int error)
{
	struct hffuse_fill_wb_data *data = wpc->wb_ctx;

	WARN_ON_ONCE(!data);

	if (data->wpa) {
		WARN_ON(!data->wpa->ia.ap.num_folios);
		hffuse_writepages_send(wpc->inode, data);
	}

	if (data->ff)
		hffuse_file_put(data->ff, false);

	return error;
}

static const struct iomap_writeback_ops hffuse_writeback_ops = {
	.writeback_range	= hffuse_iomap_writeback_range,
	.writeback_submit	= hffuse_iomap_writeback_submit,
};

static int hffuse_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct hffuse_conn *fc = get_hffuse_conn(inode);
	struct hffuse_fill_wb_data data = {};
	struct iomap_writepage_ctx wpc = {
		.inode = inode,
		.iomap.type = IOMAP_MAPPED,
		.wbc = wbc,
		.ops = &hffuse_writeback_ops,
		.wb_ctx	= &data,
	};

	if (hffuse_is_bad(inode))
		return -EIO;

	if (wbc->sync_mode == WB_SYNC_NONE &&
	    fc->num_background >= fc->congestion_threshold)
		return 0;

	return iomap_writepages(&wpc);
}

static int hffuse_launder_folio(struct folio *folio)
{
	int err = 0;
	struct hffuse_fill_wb_data data = {};
	struct iomap_writepage_ctx wpc = {
		.inode = folio->mapping->host,
		.iomap.type = IOMAP_MAPPED,
		.ops = &hffuse_writeback_ops,
		.wb_ctx	= &data,
	};

	if (folio_clear_dirty_for_io(folio)) {
		err = iomap_writeback_folio(&wpc, folio);
		err = hffuse_iomap_writeback_submit(&wpc, err);
		if (!err)
			folio_wait_writeback(folio);
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
	struct folio *folio = page_folio(vmf->page);
	struct inode *inode = file_inode(vmf->vma->vm_file);

	file_update_time(vmf->vma->vm_file);
	folio_lock(folio);
	if (folio->mapping != inode->i_mapping) {
		folio_unlock(folio);
		return VM_FAULT_NOPAGE;
	}

	folio_wait_writeback(folio);
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
	struct inode *inode = file_inode(file);
	int rc;

	/* DAX mmap is superior to direct_io mmap */
	if (HFFUSE_IS_DAX(inode))
		return hffuse_dax_mmap(file, vma);

	/*
	 * If inode is in passthrough io mode, because it has some file open
	 * in passthrough mode, either mmap to backing file or fail mmap,
	 * because mixing cached mmap and passthrough io mode is not allowed.
	 */
	if (hffuse_file_passthrough(ff))
		return hffuse_passthrough_mmap(file, vma);
	else if (hffuse_inode_backing(get_hffuse_inode(inode)))
		return -ENODEV;

	/*
	 * FOPEN_DIRECT_IO handling is special compared to O_DIRECT,
	 * as does not allow MAP_SHARED mmap without HFFUSE_DIRECT_IO_ALLOW_MMAP.
	 */
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

		/*
		 * First mmap of direct_io file enters caching inode io mode.
		 * Also waits for parallel dio writers to go into serial mode
		 * (exclusive instead of shared lock).
		 * After first mmap, the inode stays in caching io mode until
		 * the direct_io file release.
		 */
		rc = hffuse_file_cached_io_open(inode, ff);
		if (rc)
			return rc;
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
		fl->c.flc_pid = pid_nr_ns(find_pid_ns(ffl->pid, fc->pid_ns), &init_pid_ns);
		rcu_read_unlock();
		break;

	default:
		return -EIO;
	}
	fl->c.flc_type = ffl->type;
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
	inarg->owner = hffuse_lock_owner_id(fc, fl->c.flc_owner);
	inarg->lk.start = fl->fl_start;
	inarg->lk.end = fl->fl_end;
	inarg->lk.type = fl->c.flc_type;
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
	int opcode = (fl->c.flc_flags & FL_SLEEP) ? HFFUSE_SETLKW : HFFUSE_SETLK;
	struct pid *pid = fl->c.flc_type != F_UNLCK ? task_tgid(current) : NULL;
	pid_t pid_nr = pid_nr_ns(pid, fm->fc->pid_ns);
	int err;

	if (fl->fl_lmops && fl->fl_lmops->lm_grant) {
		/* NLM needs asynchronous locks, which we don't support yet */
		return -ENOLCK;
	}

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

	hffuse_do_setattr(file_mnt_idmap(file), file_dentry(file), &attr, file);
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
		err = hffuse_dax_break_layouts(inode, 0, -1);
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
		.len = min_t(size_t, len, UINT_MAX & PAGE_MASK),
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
	if (!err && outarg.size > len)
		err = -EIO;

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
	.splice_read	= hffuse_splice_read,
	.splice_write	= hffuse_splice_write,
	.unlocked_ioctl	= hffuse_file_ioctl,
	.compat_ioctl	= hffuse_file_compat_ioctl,
	.poll		= hffuse_file_poll,
	.fallocate	= hffuse_file_fallocate,
	.copy_file_range = hffuse_copy_file_range,
};

static const struct address_space_operations hffuse_file_aops  = {
	.read_folio	= hffuse_read_folio,
	.readahead	= hffuse_readahead,
	.writepages	= hffuse_writepages,
	.launder_folio	= hffuse_launder_folio,
	.dirty_folio	= iomap_dirty_folio,
	.release_folio	= iomap_release_folio,
	.invalidate_folio = iomap_invalidate_folio,
	.is_partially_uptodate = iomap_is_partially_uptodate,
	.migrate_folio	= filemap_migrate_folio,
	.bmap		= hffuse_bmap,
	.direct_IO	= hffuse_direct_IO,
};

void hffuse_init_file_inode(struct inode *inode, unsigned int flags)
{
	struct hffuse_inode *fi = get_hffuse_inode(inode);
	struct hffuse_conn *fc = get_hffuse_conn(inode);

	inode->i_fop = &hffuse_file_operations;
	inode->i_data.a_ops = &hffuse_file_aops;
	if (fc->writeback_cache)
		mapping_set_writeback_may_deadlock_on_reclaim(&inode->i_data);

	INIT_LIST_HEAD(&fi->write_files);
	INIT_LIST_HEAD(&fi->queued_writes);
	fi->writectr = 0;
	fi->iocachectr = 0;
	init_waitqueue_head(&fi->page_waitq);
	init_waitqueue_head(&fi->direct_io_waitq);

	if (IS_ENABLED(CONFIG_HFFUSE_DAX))
		hffuse_dax_inode_init(inode, flags);
}
