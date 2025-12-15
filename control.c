/*
  HFFUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "hffuse_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs_context.h>
#include <linux/namei.h>

#define HFFUSE_CTL_SUPER_MAGIC 0x65735543

/*
 * This is non-NULL when the single instance of the control filesystem
 * exists.  Protected by hffuse_mutex
 */
static struct super_block *hffuse_control_sb;

static struct hffuse_conn *hffuse_ctl_file_conn_get(struct file *file)
{
	struct hffuse_conn *fc;
	mutex_lock(&hffuse_mutex);
	fc = file_inode(file)->i_private;
	if (fc)
		fc = hffuse_conn_get(fc);
	mutex_unlock(&hffuse_mutex);
	return fc;
}

static ssize_t hffuse_conn_abort_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct hffuse_conn *fc = hffuse_ctl_file_conn_get(file);
	if (fc) {
		if (fc->abort_err)
			fc->aborted = true;
		hffuse_abort_conn(fc);
		hffuse_conn_put(fc);
	}
	return count;
}

static ssize_t hffuse_conn_waiting_read(struct file *file, char __user *buf,
				      size_t len, loff_t *ppos)
{
	char tmp[32];
	size_t size;

	if (!*ppos) {
		long value;
		struct hffuse_conn *fc = hffuse_ctl_file_conn_get(file);
		if (!fc)
			return 0;

		value = atomic_read(&fc->num_waiting);
		file->private_data = (void *)value;
		hffuse_conn_put(fc);
	}
	size = sprintf(tmp, "%ld\n", (long)file->private_data);
	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t hffuse_conn_limit_read(struct file *file, char __user *buf,
				    size_t len, loff_t *ppos, unsigned val)
{
	char tmp[32];
	size_t size = sprintf(tmp, "%u\n", val);

	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t hffuse_conn_limit_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos, unsigned *val,
				     unsigned global_limit)
{
	unsigned long t;
	unsigned limit = (1 << 16) - 1;
	int err;

	if (*ppos)
		return -EINVAL;

	err = kstrtoul_from_user(buf, count, 0, &t);
	if (err)
		return err;

	if (!capable(CAP_SYS_ADMIN))
		limit = min(limit, global_limit);

	if (t > limit)
		return -EINVAL;

	*val = t;

	return count;
}

static ssize_t hffuse_conn_max_background_read(struct file *file,
					     char __user *buf, size_t len,
					     loff_t *ppos)
{
	struct hffuse_conn *fc;
	unsigned val;

	fc = hffuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = READ_ONCE(fc->max_background);
	hffuse_conn_put(fc);

	return hffuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t hffuse_conn_max_background_write(struct file *file,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	unsigned val;
	ssize_t ret;

	ret = hffuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_bgreq);
	if (ret > 0) {
		struct hffuse_conn *fc = hffuse_ctl_file_conn_get(file);
		if (fc) {
			spin_lock(&fc->bg_lock);
			fc->max_background = val;
			fc->blocked = fc->num_background >= fc->max_background;
			if (!fc->blocked)
				wake_up(&fc->blocked_waitq);
			spin_unlock(&fc->bg_lock);
			hffuse_conn_put(fc);
		}
	}

	return ret;
}

static ssize_t hffuse_conn_congestion_threshold_read(struct file *file,
						   char __user *buf, size_t len,
						   loff_t *ppos)
{
	struct hffuse_conn *fc;
	unsigned val;

	fc = hffuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = READ_ONCE(fc->congestion_threshold);
	hffuse_conn_put(fc);

	return hffuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t hffuse_conn_congestion_threshold_write(struct file *file,
						    const char __user *buf,
						    size_t count, loff_t *ppos)
{
	unsigned val;
	struct hffuse_conn *fc;
	ssize_t ret;

	ret = hffuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_congthresh);
	if (ret <= 0)
		goto out;
	fc = hffuse_ctl_file_conn_get(file);
	if (!fc)
		goto out;

	WRITE_ONCE(fc->congestion_threshold, val);
	hffuse_conn_put(fc);
out:
	return ret;
}

static const struct file_operations hffuse_ctl_abort_ops = {
	.open = nonseekable_open,
	.write = hffuse_conn_abort_write,
};

static const struct file_operations hffuse_ctl_waiting_ops = {
	.open = nonseekable_open,
	.read = hffuse_conn_waiting_read,
};

static const struct file_operations hffuse_conn_max_background_ops = {
	.open = nonseekable_open,
	.read = hffuse_conn_max_background_read,
	.write = hffuse_conn_max_background_write,
};

static const struct file_operations hffuse_conn_congestion_threshold_ops = {
	.open = nonseekable_open,
	.read = hffuse_conn_congestion_threshold_read,
	.write = hffuse_conn_congestion_threshold_write,
};

static struct dentry *hffuse_ctl_add_dentry(struct dentry *parent,
					  struct hffuse_conn *fc,
					  const char *name,
					  int mode, int nlink,
					  const struct inode_operations *iop,
					  const struct file_operations *fop)
{
	struct dentry *dentry;
	struct inode *inode;

	dentry = d_alloc_name(parent, name);
	if (!dentry)
		return NULL;

	inode = new_inode(hffuse_control_sb);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_uid = fc->user_id;
	inode->i_gid = fc->group_id;
	simple_inode_init_ts(inode);
	/* setting ->i_op to NULL is not allowed */
	if (iop)
		inode->i_op = iop;
	inode->i_fop = fop;
	set_nlink(inode, nlink);
	inode->i_private = fc;
	d_add(dentry, inode);

	return dentry;
}

/*
 * Add a connection to the control filesystem (if it exists).  Caller
 * must hold hffuse_mutex
 */
int hffuse_ctl_add_conn(struct hffuse_conn *fc)
{
	struct dentry *parent;
	char name[32];

	if (!hffuse_control_sb || fc->no_control)
		return 0;

	parent = hffuse_control_sb->s_root;
	inc_nlink(d_inode(parent));
	sprintf(name, "%u", fc->dev);
	parent = hffuse_ctl_add_dentry(parent, fc, name, S_IFDIR | 0500, 2,
				     &simple_dir_inode_operations,
				     &simple_dir_operations);
	if (!parent)
		goto err;

	if (!hffuse_ctl_add_dentry(parent, fc, "waiting", S_IFREG | 0400, 1,
				 NULL, &hffuse_ctl_waiting_ops) ||
	    !hffuse_ctl_add_dentry(parent, fc, "abort", S_IFREG | 0200, 1,
				 NULL, &hffuse_ctl_abort_ops) ||
	    !hffuse_ctl_add_dentry(parent, fc, "max_background", S_IFREG | 0600,
				 1, NULL, &hffuse_conn_max_background_ops) ||
	    !hffuse_ctl_add_dentry(parent, fc, "congestion_threshold",
				 S_IFREG | 0600, 1, NULL,
				 &hffuse_conn_congestion_threshold_ops))
		goto err;

	return 0;

 err:
	hffuse_ctl_remove_conn(fc);
	return -ENOMEM;
}

static void remove_one(struct dentry *dentry)
{
	d_inode(dentry)->i_private = NULL;
}

/*
 * Remove a connection from the control filesystem (if it exists).
 * Caller must hold hffuse_mutex
 */
void hffuse_ctl_remove_conn(struct hffuse_conn *fc)
{
	struct dentry *dentry;
	char name[32];

	if (!hffuse_control_sb || fc->no_control)
		return;

	sprintf(name, "%u", fc->dev);
	dentry = lookup_noperm_positive_unlocked(&QSTR(name), hffuse_control_sb->s_root);
	if (!IS_ERR(dentry)) {
		simple_recursive_removal(dentry, remove_one);
		dput(dentry);	// paired with lookup_noperm_positive_unlocked()
	}
}

static int hffuse_ctl_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	static const struct tree_descr empty_descr = {""};
	struct hffuse_conn *fc;
	int err;

	err = simple_fill_super(sb, HFFUSE_CTL_SUPER_MAGIC, &empty_descr);
	if (err)
		return err;

	mutex_lock(&hffuse_mutex);
	BUG_ON(hffuse_control_sb);
	hffuse_control_sb = sb;
	list_for_each_entry(fc, &hffuse_conn_list, entry) {
		err = hffuse_ctl_add_conn(fc);
		if (err) {
			hffuse_control_sb = NULL;
			mutex_unlock(&hffuse_mutex);
			return err;
		}
	}
	mutex_unlock(&hffuse_mutex);

	return 0;
}

static int hffuse_ctl_get_tree(struct fs_context *fsc)
{
	return get_tree_single(fsc, hffuse_ctl_fill_super);
}

static const struct fs_context_operations hffuse_ctl_context_ops = {
	.get_tree	= hffuse_ctl_get_tree,
};

static int hffuse_ctl_init_fs_context(struct fs_context *fsc)
{
	fsc->ops = &hffuse_ctl_context_ops;
	return 0;
}

static void hffuse_ctl_kill_sb(struct super_block *sb)
{
	mutex_lock(&hffuse_mutex);
	hffuse_control_sb = NULL;
	mutex_unlock(&hffuse_mutex);

	kill_litter_super(sb);
}

static struct file_system_type hffuse_ctl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "hffusectl",
	.init_fs_context = hffuse_ctl_init_fs_context,
	.kill_sb	= hffuse_ctl_kill_sb,
};
MODULE_ALIAS_FS("hffusectl");

int __init hffuse_ctl_init(void)
{
	return register_filesystem(&hffuse_ctl_fs_type);
}

void __exit hffuse_ctl_cleanup(void)
{
	unregister_filesystem(&hffuse_ctl_fs_type);
}
