/* SPDX-License-Identifier: GPL-2.0
 *
 * HFFUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */
#ifndef _FS_HFFUSE_DEV_I_H
#define _FS_HFFUSE_DEV_I_H

#include <linux/types.h>

/* Ordinary requests have even IDs, while interrupts IDs are odd */
#define HFFUSE_INT_REQ_BIT (1ULL << 0)
#define HFFUSE_REQ_ID_STEP (1ULL << 1)

struct hffuse_arg;
struct hffuse_args;
struct hffuse_pqueue;
struct hffuse_req;
struct hffuse_iqueue;
struct hffuse_forget_link;

struct hffuse_copy_state {
	int write;
	struct hffuse_req *req;
	struct iov_iter *iter;
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	struct page *pg;
	unsigned int len;
	unsigned int offset;
	unsigned int move_pages:1;
	unsigned int is_uring:1;
	struct {
		unsigned int copied_sz; /* copied size into the user buffer */
	} ring;
};

static inline struct hffuse_dev *hffuse_get_dev(struct file *file)
{
	/*
	 * Lockless access is OK, because file->private data is set
	 * once during mount and is valid until the file is released.
	 */
	return READ_ONCE(file->private_data);
}

unsigned int hffuse_req_hash(u64 unique);
struct hffuse_req *hffuse_request_find(struct hffuse_pqueue *fpq, u64 unique);

void hffuse_dev_end_requests(struct list_head *head);

void hffuse_copy_init(struct hffuse_copy_state *cs, int write,
			   struct iov_iter *iter);
int hffuse_copy_args(struct hffuse_copy_state *cs, unsigned int numargs,
		   unsigned int argpages, struct hffuse_arg *args,
		   int zeroing);
int hffuse_copy_out_args(struct hffuse_copy_state *cs, struct hffuse_args *args,
		       unsigned int nbytes);
void hffuse_dev_queue_forget(struct hffuse_iqueue *fiq,
			   struct hffuse_forget_link *forget);
void hffuse_dev_queue_interrupt(struct hffuse_iqueue *fiq, struct hffuse_req *req);
bool hffuse_remove_pending_req(struct hffuse_req *req, spinlock_t *lock);

#endif

