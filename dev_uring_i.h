/* SPDX-License-Identifier: GPL-2.0
 *
 * HFFUSE: Filesystem in Userspace
 * Copyright (c) 2023-2024 DataDirect Networks.
 */

#ifndef _FS_HFFUSE_DEV_URING_I_H
#define _FS_HFFUSE_DEV_URING_I_H

#include "hffuse_i.h"

#ifdef CONFIG_HFFUSE_IO_URING

#define HFFUSE_URING_TEARDOWN_TIMEOUT (5 * HZ)
#define HFFUSE_URING_TEARDOWN_INTERVAL (HZ/20)

enum hffuse_ring_req_state {
	FRRS_INVALID = 0,

	/* The ring entry received from userspace and it is being processed */
	FRRS_COMMIT,

	/* The ring entry is waiting for new hffuse requests */
	FRRS_AVAILABLE,

	/* The ring entry got assigned a hffuse req */
	FRRS_HFFUSE_REQ,

	/* The ring entry is in or on the way to user space */
	FRRS_USERSPACE,

	/* The ring entry is in teardown */
	FRRS_TEARDOWN,

	/* The ring entry is released, but not freed yet */
	FRRS_RELEASED,
};

/** A hffuse ring entry, part of the ring queue */
struct hffuse_ring_ent {
	/* userspace buffer */
	struct hffuse_uring_req_header __user *headers;
	void __user *payload;

	/* the ring queue that owns the request */
	struct hffuse_ring_queue *queue;

	/* fields below are protected by queue->lock */

	struct io_uring_cmd *cmd;

	struct list_head list;

	enum hffuse_ring_req_state state;

	struct hffuse_req *hffuse_req;
};

struct hffuse_ring_queue {
	/*
	 * back pointer to the main hffuse uring structure that holds this
	 * queue
	 */
	struct hffuse_ring *ring;

	/* queue id, corresponds to the cpu core */
	unsigned int qid;

	/*
	 * queue lock, taken when any value in the queue changes _and_ also
	 * a ring entry state changes.
	 */
	spinlock_t lock;

	/* available ring entries (struct hffuse_ring_ent) */
	struct list_head ent_avail_queue;

	/*
	 * entries in the process of being committed or in the process
	 * to be sent to userspace
	 */
	struct list_head ent_w_req_queue;
	struct list_head ent_commit_queue;

	/* entries in userspace */
	struct list_head ent_in_userspace;

	/* entries that are released */
	struct list_head ent_released;

	/* hffuse requests waiting for an entry slot */
	struct list_head hffuse_req_queue;

	/* background hffuse requests */
	struct list_head hffuse_req_bg_queue;

	struct hffuse_pqueue fpq;

	unsigned int active_background;

	bool stopped;
};

/**
 * Describes if uring is for communication and holds alls the data needed
 * for uring communication
 */
struct hffuse_ring {
	/* back pointer */
	struct hffuse_conn *fc;

	/* number of ring queues */
	size_t nr_queues;

	/* maximum payload/arg size */
	size_t max_payload_sz;

	struct hffuse_ring_queue **queues;

	/*
	 * Log ring entry states on stop when entries cannot be released
	 */
	unsigned int stop_debug_log : 1;

	wait_queue_head_t stop_waitq;

	/* async tear down */
	struct delayed_work async_teardown_work;

	/* log */
	unsigned long teardown_time;

	atomic_t queue_refs;

	bool ready;
};

bool hffuse_uring_enabled(void);
void hffuse_uring_destruct(struct hffuse_conn *fc);
void hffuse_uring_stop_queues(struct hffuse_ring *ring);
void hffuse_uring_abort_end_requests(struct hffuse_ring *ring);
int hffuse_uring_cmd(struct io_uring_cmd *cmd, unsigned int issue_flags);
void hffuse_uring_queue_hffuse_req(struct hffuse_iqueue *fiq, struct hffuse_req *req);
bool hffuse_uring_queue_bq_req(struct hffuse_req *req);
bool hffuse_uring_remove_pending_req(struct hffuse_req *req);

static inline void hffuse_uring_abort(struct hffuse_conn *fc)
{
	struct hffuse_ring *ring = fc->ring;

	if (ring == NULL)
		return;

	if (atomic_read(&ring->queue_refs) > 0) {
		hffuse_uring_abort_end_requests(ring);
		hffuse_uring_stop_queues(ring);
	}
}

static inline void hffuse_uring_wait_stopped_queues(struct hffuse_conn *fc)
{
	struct hffuse_ring *ring = fc->ring;

	if (ring)
		wait_event(ring->stop_waitq,
			   atomic_read(&ring->queue_refs) == 0);
}

static inline bool hffuse_uring_ready(struct hffuse_conn *fc)
{
	return fc->ring && fc->ring->ready;
}

#else /* CONFIG_HFFUSE_IO_URING */

struct hffuse_ring;

static inline void hffuse_uring_create(struct hffuse_conn *fc)
{
}

static inline void hffuse_uring_destruct(struct hffuse_conn *fc)
{
}

static inline bool hffuse_uring_enabled(void)
{
	return false;
}

static inline void hffuse_uring_abort(struct hffuse_conn *fc)
{
}

static inline void hffuse_uring_wait_stopped_queues(struct hffuse_conn *fc)
{
}

static inline bool hffuse_uring_ready(struct hffuse_conn *fc)
{
	return false;
}

static inline bool hffuse_uring_remove_pending_req(struct hffuse_req *req)
{
	return false;
}

#endif /* CONFIG_HFFUSE_IO_URING */

#endif /* _FS_HFFUSE_DEV_URING_I_H */
