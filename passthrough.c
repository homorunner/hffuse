// SPDX-License-Identifier: GPL-2.0
/*
 * HFFUSE passthrough to backing file.
 *
 * Copyright (c) 2023 CTERA Networks.
 */

#include "hffuse_i.h"

#include <linux/file.h>
#include <linux/backing-file.h>
#include <linux/splice.h>

static void hffuse_file_accessed(struct file *file)
{
	struct inode *inode = file_inode(file);

	hffuse_invalidate_atime(inode);
}

static void hffuse_passthrough_end_write(struct kiocb *iocb, ssize_t ret)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	hffuse_write_update_attr(inode, iocb->ki_pos, ret);
}

ssize_t hffuse_passthrough_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct hffuse_file *ff = file->private_data;
	struct file *backing_file = hffuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.accessed = hffuse_file_accessed,
	};


	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu\n", __func__,
		 backing_file, iocb->ki_pos, count);

	if (!count)
		return 0;

	ret = backing_file_read_iter(backing_file, iter, iocb, iocb->ki_flags,
				     &ctx);

	return ret;
}

ssize_t hffuse_passthrough_write_iter(struct kiocb *iocb,
				    struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct hffuse_file *ff = file->private_data;
	struct file *backing_file = hffuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.end_write = hffuse_passthrough_end_write,
	};

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu\n", __func__,
		 backing_file, iocb->ki_pos, count);

	if (!count)
		return 0;

	inode_lock(inode);
	ret = backing_file_write_iter(backing_file, iter, iocb, iocb->ki_flags,
				      &ctx);
	inode_unlock(inode);

	return ret;
}

ssize_t hffuse_passthrough_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len, unsigned int flags)
{
	struct hffuse_file *ff = in->private_data;
	struct file *backing_file = hffuse_file_passthrough(ff);
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.accessed = hffuse_file_accessed,
	};
	struct kiocb iocb;
	ssize_t ret;

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 backing_file, *ppos, len, flags);

	init_sync_kiocb(&iocb, in);
	iocb.ki_pos = *ppos;
	ret = backing_file_splice_read(backing_file, &iocb, pipe, len, flags, &ctx);
	*ppos = iocb.ki_pos;

	return ret;
}

ssize_t hffuse_passthrough_splice_write(struct pipe_inode_info *pipe,
				      struct file *out, loff_t *ppos,
				      size_t len, unsigned int flags)
{
	struct hffuse_file *ff = out->private_data;
	struct file *backing_file = hffuse_file_passthrough(ff);
	struct inode *inode = file_inode(out);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.end_write = hffuse_passthrough_end_write,
	};
	struct kiocb iocb;

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 backing_file, *ppos, len, flags);

	inode_lock(inode);
	init_sync_kiocb(&iocb, out);
	iocb.ki_pos = *ppos;
	ret = backing_file_splice_write(pipe, backing_file, &iocb, len, flags, &ctx);
	*ppos = iocb.ki_pos;
	inode_unlock(inode);

	return ret;
}

ssize_t hffuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct hffuse_file *ff = file->private_data;
	struct file *backing_file = hffuse_file_passthrough(ff);
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.accessed = hffuse_file_accessed,
	};

	pr_debug("%s: backing_file=0x%p, start=%lu, end=%lu\n", __func__,
		 backing_file, vma->vm_start, vma->vm_end);

	return backing_file_mmap(backing_file, vma, &ctx);
}

struct hffuse_backing *hffuse_backing_get(struct hffuse_backing *fb)
{
	if (fb && refcount_inc_not_zero(&fb->count))
		return fb;
	return NULL;
}

static void hffuse_backing_free(struct hffuse_backing *fb)
{
	pr_debug("%s: fb=0x%p\n", __func__, fb);

	if (fb->file)
		fput(fb->file);
	put_cred(fb->cred);
	kfree_rcu(fb, rcu);
}

void hffuse_backing_put(struct hffuse_backing *fb)
{
	if (fb && refcount_dec_and_test(&fb->count))
		hffuse_backing_free(fb);
}

void hffuse_backing_files_init(struct hffuse_conn *fc)
{
	idr_init(&fc->backing_files_map);
}

static int hffuse_backing_id_alloc(struct hffuse_conn *fc, struct hffuse_backing *fb)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&fc->lock);
	/* FIXME: xarray might be space inefficient */
	id = idr_alloc_cyclic(&fc->backing_files_map, fb, 1, 0, GFP_ATOMIC);
	spin_unlock(&fc->lock);
	idr_preload_end();

	WARN_ON_ONCE(id == 0);
	return id;
}

static struct hffuse_backing *hffuse_backing_id_remove(struct hffuse_conn *fc,
						   int id)
{
	struct hffuse_backing *fb;

	spin_lock(&fc->lock);
	fb = idr_remove(&fc->backing_files_map, id);
	spin_unlock(&fc->lock);

	return fb;
}

static int hffuse_backing_id_free(int id, void *p, void *data)
{
	struct hffuse_backing *fb = p;

	WARN_ON_ONCE(refcount_read(&fb->count) != 1);
	hffuse_backing_free(fb);
	return 0;
}

void hffuse_backing_files_free(struct hffuse_conn *fc)
{
	idr_for_each(&fc->backing_files_map, hffuse_backing_id_free, NULL);
	idr_destroy(&fc->backing_files_map);
}

int hffuse_backing_open(struct hffuse_conn *fc, struct hffuse_backing_map *map)
{
	struct file *file;
	struct super_block *backing_sb;
	struct hffuse_backing *fb = NULL;
	int res;

	pr_debug("%s: fd=%d flags=0x%x\n", __func__, map->fd, map->flags);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	res = -EPERM;
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		goto out;

	res = -EINVAL;
	if (map->flags || map->padding)
		goto out;

	file = fget_raw(map->fd);
	res = -EBADF;
	if (!file)
		goto out;

	/* read/write/splice/mmap passthrough only relevant for regular files */
	res = d_is_dir(file->f_path.dentry) ? -EISDIR : -EINVAL;
	if (!d_is_reg(file->f_path.dentry))
		goto out_fput;

	backing_sb = file_inode(file)->i_sb;
	res = -ELOOP;
	if (backing_sb->s_stack_depth >= fc->max_stack_depth)
		goto out_fput;

	fb = kmalloc(sizeof(struct hffuse_backing), GFP_KERNEL);
	res = -ENOMEM;
	if (!fb)
		goto out_fput;

	fb->file = file;
	fb->cred = prepare_creds();
	refcount_set(&fb->count, 1);

	res = hffuse_backing_id_alloc(fc, fb);
	if (res < 0) {
		hffuse_backing_free(fb);
		fb = NULL;
	}

out:
	pr_debug("%s: fb=0x%p, ret=%i\n", __func__, fb, res);

	return res;

out_fput:
	fput(file);
	goto out;
}

int hffuse_backing_close(struct hffuse_conn *fc, int backing_id)
{
	struct hffuse_backing *fb = NULL;
	int err;

	pr_debug("%s: backing_id=%d\n", __func__, backing_id);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	err = -EPERM;
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		goto out;

	err = -EINVAL;
	if (backing_id <= 0)
		goto out;

	err = -ENOENT;
	fb = hffuse_backing_id_remove(fc, backing_id);
	if (!fb)
		goto out;

	hffuse_backing_put(fb);
	err = 0;
out:
	pr_debug("%s: fb=0x%p, err=%i\n", __func__, fb, err);

	return err;
}

/*
 * Setup passthrough to a backing file.
 *
 * Returns an fb object with elevated refcount to be stored in hffuse inode.
 */
struct hffuse_backing *hffuse_passthrough_open(struct file *file,
					   struct inode *inode,
					   int backing_id)
{
	struct hffuse_file *ff = file->private_data;
	struct hffuse_conn *fc = ff->fm->fc;
	struct hffuse_backing *fb = NULL;
	struct file *backing_file;
	int err;

	err = -EINVAL;
	if (backing_id <= 0)
		goto out;

	rcu_read_lock();
	fb = idr_find(&fc->backing_files_map, backing_id);
	fb = hffuse_backing_get(fb);
	rcu_read_unlock();

	err = -ENOENT;
	if (!fb)
		goto out;

	/* Allocate backing file per hffuse file to store hffuse path */
	backing_file = backing_file_open(&file->f_path, file->f_flags,
					 &fb->file->f_path, fb->cred);
	err = PTR_ERR(backing_file);
	if (IS_ERR(backing_file)) {
		hffuse_backing_put(fb);
		goto out;
	}

	err = 0;
	ff->passthrough = backing_file;
	ff->cred = get_cred(fb->cred);
out:
	pr_debug("%s: backing_id=%d, fb=0x%p, backing_file=0x%p, err=%i\n", __func__,
		 backing_id, fb, ff->passthrough, err);

	return err ? ERR_PTR(err) : fb;
}

void hffuse_passthrough_release(struct hffuse_file *ff, struct hffuse_backing *fb)
{
	pr_debug("%s: fb=0x%p, backing_file=0x%p\n", __func__,
		 fb, ff->passthrough);

	fput(ff->passthrough);
	ff->passthrough = NULL;
	put_cred(ff->cred);
	ff->cred = NULL;
}
