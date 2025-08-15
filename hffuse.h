/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
    This file defines the kernel interface of HFFUSE
    Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    This -- and only this -- header file may also be distributed under
    the terms of the BSD Licence as follows:

    Copyright (C) 2001-2007 Miklos Szeredi. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.
*/

/*
 * This file defines the kernel interface of HFFUSE
 *
 * Protocol changelog:
 *
 * 7.1:
 *  - add the following messages:
 *      HFFUSE_SETATTR, HFFUSE_SYMLINK, HFFUSE_MKNOD, HFFUSE_MKDIR, HFFUSE_UNLINK,
 *      HFFUSE_RMDIR, HFFUSE_RENAME, HFFUSE_LINK, HFFUSE_OPEN, HFFUSE_READ, HFFUSE_WRITE,
 *      HFFUSE_RELEASE, HFFUSE_FSYNC, HFFUSE_FLUSH, HFFUSE_SETXATTR, HFFUSE_GETXATTR,
 *      HFFUSE_LISTXATTR, HFFUSE_REMOVEXATTR, HFFUSE_OPENDIR, HFFUSE_READDIR,
 *      HFFUSE_RELEASEDIR
 *  - add padding to messages to accommodate 32-bit servers on 64-bit kernels
 *
 * 7.2:
 *  - add FOPEN_DIRECT_IO and FOPEN_KEEP_CACHE flags
 *  - add HFFUSE_FSYNCDIR message
 *
 * 7.3:
 *  - add HFFUSE_ACCESS message
 *  - add HFFUSE_CREATE message
 *  - add filehandle to hffuse_setattr_in
 *
 * 7.4:
 *  - add frsize to hffuse_kstatfs
 *  - clean up request size limit checking
 *
 * 7.5:
 *  - add flags and max_write to hffuse_init_out
 *
 * 7.6:
 *  - add max_readahead to hffuse_init_in and hffuse_init_out
 *
 * 7.7:
 *  - add HFFUSE_INTERRUPT message
 *  - add POSIX file lock support
 *
 * 7.8:
 *  - add lock_owner and flags fields to hffuse_release_in
 *  - add HFFUSE_BMAP message
 *  - add HFFUSE_DESTROY message
 *
 * 7.9:
 *  - new hffuse_getattr_in input argument of GETATTR
 *  - add lk_flags in hffuse_lk_in
 *  - add lock_owner field to hffuse_setattr_in, hffuse_read_in and hffuse_write_in
 *  - add blksize field to hffuse_attr
 *  - add file flags field to hffuse_read_in and hffuse_write_in
 *  - Add ATIME_NOW and MTIME_NOW flags to hffuse_setattr_in
 *
 * 7.10
 *  - add nonseekable open flag
 *
 * 7.11
 *  - add IOCTL message
 *  - add unsolicited notification support
 *  - add POLL message and NOTIFY_POLL notification
 *
 * 7.12
 *  - add umask flag to input argument of create, mknod and mkdir
 *  - add notification messages for invalidation of inodes and
 *    directory entries
 *
 * 7.13
 *  - make max number of background requests and congestion threshold
 *    tunables
 *
 * 7.14
 *  - add splice support to hffuse device
 *
 * 7.15
 *  - add store notify
 *  - add retrieve notify
 *
 * 7.16
 *  - add BATCH_FORGET request
 *  - HFFUSE_IOCTL_UNRESTRICTED shall now return with array of 'struct
 *    hffuse_ioctl_iovec' instead of ambiguous 'struct iovec'
 *  - add HFFUSE_IOCTL_32BIT flag
 *
 * 7.17
 *  - add HFFUSE_FLOCK_LOCKS and HFFUSE_RELEASE_FLOCK_UNLOCK
 *
 * 7.18
 *  - add HFFUSE_IOCTL_DIR flag
 *  - add HFFUSE_NOTIFY_DELETE
 *
 * 7.19
 *  - add HFFUSE_FALLOCATE
 *
 * 7.20
 *  - add HFFUSE_AUTO_INVAL_DATA
 *
 * 7.21
 *  - add HFFUSE_READDIRPLUS
 *  - send the requested events in POLL request
 *
 * 7.22
 *  - add HFFUSE_ASYNC_DIO
 *
 * 7.23
 *  - add HFFUSE_WRITEBACK_CACHE
 *  - add time_gran to hffuse_init_out
 *  - add reserved space to hffuse_init_out
 *  - add FATTR_CTIME
 *  - add ctime and ctimensec to hffuse_setattr_in
 *  - add HFFUSE_RENAME2 request
 *  - add HFFUSE_NO_OPEN_SUPPORT flag
 *
 *  7.24
 *  - add HFFUSE_LSEEK for SEEK_HOLE and SEEK_DATA support
 *
 *  7.25
 *  - add HFFUSE_PARALLEL_DIROPS
 *
 *  7.26
 *  - add HFFUSE_HANDLE_KILLPRIV
 *  - add HFFUSE_POSIX_ACL
 *
 *  7.27
 *  - add HFFUSE_ABORT_ERROR
 *
 *  7.28
 *  - add HFFUSE_COPY_FILE_RANGE
 *  - add FOPEN_CACHE_DIR
 *  - add HFFUSE_MAX_PAGES, add max_pages to init_out
 *  - add HFFUSE_CACHE_SYMLINKS
 *
 *  7.29
 *  - add HFFUSE_NO_OPENDIR_SUPPORT flag
 *
 *  7.30
 *  - add HFFUSE_EXPLICIT_INVAL_DATA
 *  - add HFFUSE_IOCTL_COMPAT_X32
 *
 *  7.31
 *  - add HFFUSE_WRITE_KILL_PRIV flag
 *  - add HFFUSE_SETUPMAPPING and HFFUSE_REMOVEMAPPING
 *  - add map_alignment to hffuse_init_out, add HFFUSE_MAP_ALIGNMENT flag
 *
 *  7.32
 *  - add flags to hffuse_attr, add HFFUSE_ATTR_SUBMOUNT, add HFFUSE_SUBMOUNTS
 *
 *  7.33
 *  - add HFFUSE_HANDLE_KILLPRIV_V2, HFFUSE_WRITE_KILL_SUIDGID, FATTR_KILL_SUIDGID
 *  - add HFFUSE_OPEN_KILL_SUIDGID
 *  - extend hffuse_setxattr_in, add HFFUSE_SETXATTR_EXT
 *  - add HFFUSE_SETXATTR_ACL_KILL_SGID
 *
 *  7.34
 *  - add HFFUSE_SYNCFS
 *
 *  7.35
 *  - add FOPEN_NOFLUSH
 *
 *  7.36
 *  - extend hffuse_init_in with reserved fields, add HFFUSE_INIT_EXT init flag
 *  - add flags2 to hffuse_init_in and hffuse_init_out
 *  - add HFFUSE_SECURITY_CTX init flag
 *  - add security context to create, mkdir, symlink, and mknod requests
 *  - add HFFUSE_HAS_INODE_DAX, HFFUSE_ATTR_DAX
 *
 *  7.37
 *  - add HFFUSE_TMPFILE
 *
 *  7.38
 *  - add HFFUSE_EXPIRE_ONLY flag to hffuse_notify_inval_entry
 *  - add FOPEN_PARALLEL_DIRECT_WRITES
 *  - add total_extlen to hffuse_in_header
 *  - add HFFUSE_MAX_NR_SECCTX
 *  - add extension header
 *  - add HFFUSE_EXT_GROUPS
 *  - add HFFUSE_CREATE_SUPP_GROUP
 *  - add HFFUSE_HAS_EXPIRE_ONLY
 *
 *  7.39
 *  - add HFFUSE_DIRECT_IO_ALLOW_MMAP
 *  - add HFFUSE_STATX and related structures
 */

#ifndef _LINUX_HFFUSE_H
#define _LINUX_HFFUSE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*
 * Version negotiation:
 *
 * Both the kernel and userspace send the version they support in the
 * INIT request and reply respectively.
 *
 * If the major versions match then both shall use the smallest
 * of the two minor versions for communication.
 *
 * If the kernel supports a larger major version, then userspace shall
 * reply with the major version it supports, ignore the rest of the
 * INIT message and expect a new INIT message from the kernel with a
 * matching major version.
 *
 * If the library supports a larger major version, then it shall fall
 * back to the major protocol version sent by the kernel for
 * communication and reply with that major version (and an arbitrary
 * supported minor version).
 */

/** Version number of this interface */
#define HFFUSE_KERNEL_VERSION 7

/** Minor version number of this interface */
#define HFFUSE_KERNEL_MINOR_VERSION 39

/** The node ID of the root inode */
#define HFFUSE_ROOT_ID 1

/* Make sure all structures are padded to 64bit boundary, so 32bit
   userspace works under 64bit kernels */

struct hffuse_attr {
	uint64_t	ino;
	uint64_t	size;
	uint64_t	blocks;
	uint64_t	atime;
	uint64_t	mtime;
	uint64_t	ctime;
	uint32_t	atimensec;
	uint32_t	mtimensec;
	uint32_t	ctimensec;
	uint32_t	mode;
	uint32_t	nlink;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	rdev;
	uint32_t	blksize;
	uint32_t	flags;
};

/*
 * The following structures are bit-for-bit compatible with the statx(2) ABI in
 * Linux.
 */
struct hffuse_sx_time {
	int64_t		tv_sec;
	uint32_t	tv_nsec;
	int32_t		__reserved;
};

struct hffuse_statx {
	uint32_t	mask;
	uint32_t	blksize;
	uint64_t	attributes;
	uint32_t	nlink;
	uint32_t	uid;
	uint32_t	gid;
	uint16_t	mode;
	uint16_t	__spare0[1];
	uint64_t	ino;
	uint64_t	size;
	uint64_t	blocks;
	uint64_t	attributes_mask;
	struct hffuse_sx_time	atime;
	struct hffuse_sx_time	btime;
	struct hffuse_sx_time	ctime;
	struct hffuse_sx_time	mtime;
	uint32_t	rdev_major;
	uint32_t	rdev_minor;
	uint32_t	dev_major;
	uint32_t	dev_minor;
	uint64_t	__spare2[14];
};

struct hffuse_kstatfs {
	uint64_t	blocks;
	uint64_t	bfree;
	uint64_t	bavail;
	uint64_t	files;
	uint64_t	ffree;
	uint32_t	bsize;
	uint32_t	namelen;
	uint32_t	frsize;
	uint32_t	padding;
	uint32_t	spare[6];
};

struct hffuse_file_lock {
	uint64_t	start;
	uint64_t	end;
	uint32_t	type;
	uint32_t	pid; /* tgid */
};

/**
 * Bitmasks for hffuse_setattr_in.valid
 */
#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_ATIME	(1 << 4)
#define FATTR_MTIME	(1 << 5)
#define FATTR_FH	(1 << 6)
#define FATTR_ATIME_NOW	(1 << 7)
#define FATTR_MTIME_NOW	(1 << 8)
#define FATTR_LOCKOWNER	(1 << 9)
#define FATTR_CTIME	(1 << 10)
#define FATTR_KILL_SUIDGID	(1 << 11)

/**
 * Flags returned by the OPEN request
 *
 * FOPEN_DIRECT_IO: bypass page cache for this open file
 * FOPEN_KEEP_CACHE: don't invalidate the data cache on open
 * FOPEN_NONSEEKABLE: the file is not seekable
 * FOPEN_CACHE_DIR: allow caching this directory
 * FOPEN_STREAM: the file is stream-like (no file position at all)
 * FOPEN_NOFLUSH: don't flush data cache on close (unless HFFUSE_WRITEBACK_CACHE)
 * FOPEN_PARALLEL_DIRECT_WRITES: Allow concurrent direct writes on the same inode
 */
#define FOPEN_DIRECT_IO		(1 << 0)
#define FOPEN_KEEP_CACHE	(1 << 1)
#define FOPEN_NONSEEKABLE	(1 << 2)
#define FOPEN_CACHE_DIR		(1 << 3)
#define FOPEN_STREAM		(1 << 4)
#define FOPEN_NOFLUSH		(1 << 5)
#define FOPEN_PARALLEL_DIRECT_WRITES	(1 << 6)

/**
 * INIT request/reply flags
 *
 * HFFUSE_ASYNC_READ: asynchronous read requests
 * HFFUSE_POSIX_LOCKS: remote locking for POSIX file locks
 * HFFUSE_FILE_OPS: kernel sends file handle for fstat, etc... (not yet supported)
 * HFFUSE_ATOMIC_O_TRUNC: handles the O_TRUNC open flag in the filesystem
 * HFFUSE_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * HFFUSE_BIG_WRITES: filesystem can handle write size larger than 4kB
 * HFFUSE_DONT_MASK: don't apply umask to file mode on create operations
 * HFFUSE_SPLICE_WRITE: kernel supports splice write on the device
 * HFFUSE_SPLICE_MOVE: kernel supports splice move on the device
 * HFFUSE_SPLICE_READ: kernel supports splice read on the device
 * HFFUSE_FLOCK_LOCKS: remote locking for BSD style file locks
 * HFFUSE_HAS_IOCTL_DIR: kernel supports ioctl on directories
 * HFFUSE_AUTO_INVAL_DATA: automatically invalidate cached pages
 * HFFUSE_DO_READDIRPLUS: do READDIRPLUS (READDIR+LOOKUP in one)
 * HFFUSE_READDIRPLUS_AUTO: adaptive readdirplus
 * HFFUSE_ASYNC_DIO: asynchronous direct I/O submission
 * HFFUSE_WRITEBACK_CACHE: use writeback cache for buffered writes
 * HFFUSE_NO_OPEN_SUPPORT: kernel supports zero-message opens
 * HFFUSE_PARALLEL_DIROPS: allow parallel lookups and readdir
 * HFFUSE_HANDLE_KILLPRIV: fs handles killing suid/sgid/cap on write/chown/trunc
 * HFFUSE_POSIX_ACL: filesystem supports posix acls
 * HFFUSE_ABORT_ERROR: reading the device after abort returns ECONNABORTED
 * HFFUSE_MAX_PAGES: init_out.max_pages contains the max number of req pages
 * HFFUSE_CACHE_SYMLINKS: cache READLINK responses
 * HFFUSE_NO_OPENDIR_SUPPORT: kernel supports zero-message opendir
 * HFFUSE_EXPLICIT_INVAL_DATA: only invalidate cached pages on explicit request
 * HFFUSE_MAP_ALIGNMENT: init_out.map_alignment contains log2(byte alignment) for
 *		       foffset and moffset fields in struct
 *		       hffuse_setupmapping_out and hffuse_removemapping_one.
 * HFFUSE_SUBMOUNTS: kernel supports auto-mounting directory submounts
 * HFFUSE_HANDLE_KILLPRIV_V2: fs kills suid/sgid/cap on write/chown/trunc.
 *			Upon write/truncate suid/sgid is only killed if caller
 *			does not have CAP_FSETID. Additionally upon
 *			write/truncate sgid is killed only if file has group
 *			execute permission. (Same as Linux VFS behavior).
 * HFFUSE_SETXATTR_EXT:	Server supports extended struct hffuse_setxattr_in
 * HFFUSE_INIT_EXT: extended hffuse_init_in request
 * HFFUSE_INIT_RESERVED: reserved, do not use
 * HFFUSE_SECURITY_CTX:	add security context to create, mkdir, symlink, and
 *			mknod
 * HFFUSE_HAS_INODE_DAX:  use per inode DAX
 * HFFUSE_CREATE_SUPP_GROUP: add supplementary group info to create, mkdir,
 *			symlink and mknod (single group that matches parent)
 * HFFUSE_HAS_EXPIRE_ONLY: kernel supports expiry-only entry invalidation
 * HFFUSE_DIRECT_IO_ALLOW_MMAP: allow shared mmap in FOPEN_DIRECT_IO mode.
 */
#define HFFUSE_ASYNC_READ		(1 << 0)
#define HFFUSE_POSIX_LOCKS	(1 << 1)
#define HFFUSE_FILE_OPS		(1 << 2)
#define HFFUSE_ATOMIC_O_TRUNC	(1 << 3)
#define HFFUSE_EXPORT_SUPPORT	(1 << 4)
#define HFFUSE_BIG_WRITES		(1 << 5)
#define HFFUSE_DONT_MASK		(1 << 6)
#define HFFUSE_SPLICE_WRITE	(1 << 7)
#define HFFUSE_SPLICE_MOVE	(1 << 8)
#define HFFUSE_SPLICE_READ	(1 << 9)
#define HFFUSE_FLOCK_LOCKS	(1 << 10)
#define HFFUSE_HAS_IOCTL_DIR	(1 << 11)
#define HFFUSE_AUTO_INVAL_DATA	(1 << 12)
#define HFFUSE_DO_READDIRPLUS	(1 << 13)
#define HFFUSE_READDIRPLUS_AUTO	(1 << 14)
#define HFFUSE_ASYNC_DIO		(1 << 15)
#define HFFUSE_WRITEBACK_CACHE	(1 << 16)
#define HFFUSE_NO_OPEN_SUPPORT	(1 << 17)
#define HFFUSE_PARALLEL_DIROPS    (1 << 18)
#define HFFUSE_HANDLE_KILLPRIV	(1 << 19)
#define HFFUSE_POSIX_ACL		(1 << 20)
#define HFFUSE_ABORT_ERROR	(1 << 21)
#define HFFUSE_MAX_PAGES		(1 << 22)
#define HFFUSE_CACHE_SYMLINKS	(1 << 23)
#define HFFUSE_NO_OPENDIR_SUPPORT (1 << 24)
#define HFFUSE_EXPLICIT_INVAL_DATA (1 << 25)
#define HFFUSE_MAP_ALIGNMENT	(1 << 26)
#define HFFUSE_SUBMOUNTS		(1 << 27)
#define HFFUSE_HANDLE_KILLPRIV_V2	(1 << 28)
#define HFFUSE_SETXATTR_EXT	(1 << 29)
#define HFFUSE_INIT_EXT		(1 << 30)
#define HFFUSE_INIT_RESERVED	(1 << 31)
/* bits 32..63 get shifted down 32 bits into the flags2 field */
#define HFFUSE_SECURITY_CTX	(1ULL << 32)
#define HFFUSE_HAS_INODE_DAX	(1ULL << 33)
#define HFFUSE_CREATE_SUPP_GROUP	(1ULL << 34)
#define HFFUSE_HAS_EXPIRE_ONLY	(1ULL << 35)
#define HFFUSE_DIRECT_IO_ALLOW_MMAP (1ULL << 36)

/* Obsolete alias for HFFUSE_DIRECT_IO_ALLOW_MMAP */
#define HFFUSE_DIRECT_IO_RELAX	HFFUSE_DIRECT_IO_ALLOW_MMAP

/**
 * CUSE INIT request/reply flags
 *
 * CUSE_UNRESTRICTED_IOCTL:  use unrestricted ioctl
 */
#define CUSE_UNRESTRICTED_IOCTL	(1 << 0)

/**
 * Release flags
 */
#define HFFUSE_RELEASE_FLUSH	(1 << 0)
#define HFFUSE_RELEASE_FLOCK_UNLOCK	(1 << 1)

/**
 * Getattr flags
 */
#define HFFUSE_GETATTR_FH		(1 << 0)

/**
 * Lock flags
 */
#define HFFUSE_LK_FLOCK		(1 << 0)

/**
 * WRITE flags
 *
 * HFFUSE_WRITE_CACHE: delayed write from page cache, file handle is guessed
 * HFFUSE_WRITE_LOCKOWNER: lock_owner field is valid
 * HFFUSE_WRITE_KILL_SUIDGID: kill suid and sgid bits
 */
#define HFFUSE_WRITE_CACHE	(1 << 0)
#define HFFUSE_WRITE_LOCKOWNER	(1 << 1)
#define HFFUSE_WRITE_KILL_SUIDGID (1 << 2)

/* Obsolete alias; this flag implies killing suid/sgid only. */
#define HFFUSE_WRITE_KILL_PRIV	HFFUSE_WRITE_KILL_SUIDGID

/**
 * Read flags
 */
#define HFFUSE_READ_LOCKOWNER	(1 << 1)

/**
 * Ioctl flags
 *
 * HFFUSE_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * HFFUSE_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * HFFUSE_IOCTL_RETRY: retry with new iovecs
 * HFFUSE_IOCTL_32BIT: 32bit ioctl
 * HFFUSE_IOCTL_DIR: is a directory
 * HFFUSE_IOCTL_COMPAT_X32: x32 compat ioctl on 64bit machine (64bit time_t)
 *
 * HFFUSE_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
#define HFFUSE_IOCTL_COMPAT	(1 << 0)
#define HFFUSE_IOCTL_UNRESTRICTED	(1 << 1)
#define HFFUSE_IOCTL_RETRY	(1 << 2)
#define HFFUSE_IOCTL_32BIT	(1 << 3)
#define HFFUSE_IOCTL_DIR		(1 << 4)
#define HFFUSE_IOCTL_COMPAT_X32	(1 << 5)

#define HFFUSE_IOCTL_MAX_IOV	256

/**
 * Poll flags
 *
 * HFFUSE_POLL_SCHEDULE_NOTIFY: request poll notify
 */
#define HFFUSE_POLL_SCHEDULE_NOTIFY (1 << 0)

/**
 * Fsync flags
 *
 * HFFUSE_FSYNC_FDATASYNC: Sync data only, not metadata
 */
#define HFFUSE_FSYNC_FDATASYNC	(1 << 0)

/**
 * hffuse_attr flags
 *
 * HFFUSE_ATTR_SUBMOUNT: Object is a submount root
 * HFFUSE_ATTR_DAX: Enable DAX for this file in per inode DAX mode
 */
#define HFFUSE_ATTR_SUBMOUNT      (1 << 0)
#define HFFUSE_ATTR_DAX		(1 << 1)

/**
 * Open flags
 * HFFUSE_OPEN_KILL_SUIDGID: Kill suid and sgid if executable
 */
#define HFFUSE_OPEN_KILL_SUIDGID	(1 << 0)

/**
 * setxattr flags
 * HFFUSE_SETXATTR_ACL_KILL_SGID: Clear SGID when system.posix_acl_access is set
 */
#define HFFUSE_SETXATTR_ACL_KILL_SGID	(1 << 0)

/**
 * notify_inval_entry flags
 * HFFUSE_EXPIRE_ONLY
 */
#define HFFUSE_EXPIRE_ONLY		(1 << 0)

/**
 * extension type
 * HFFUSE_MAX_NR_SECCTX: maximum value of &hffuse_secctx_header.nr_secctx
 * HFFUSE_EXT_GROUPS: &hffuse_supp_groups extension
 */
enum hffuse_ext_type {
	/* Types 0..31 are reserved for hffuse_secctx_header */
	HFFUSE_MAX_NR_SECCTX	= 31,
	HFFUSE_EXT_GROUPS		= 32,
};

enum hffuse_opcode {
	HFFUSE_LOOKUP		= 1,
	HFFUSE_FORGET		= 2,  /* no reply */
	HFFUSE_GETATTR		= 3,
	HFFUSE_SETATTR		= 4,
	HFFUSE_READLINK		= 5,
	HFFUSE_SYMLINK		= 6,
	HFFUSE_MKNOD		= 8,
	HFFUSE_MKDIR		= 9,
	HFFUSE_UNLINK		= 10,
	HFFUSE_RMDIR		= 11,
	HFFUSE_RENAME		= 12,
	HFFUSE_LINK		= 13,
	HFFUSE_OPEN		= 14,
	HFFUSE_READ		= 15,
	HFFUSE_WRITE		= 16,
	HFFUSE_STATFS		= 17,
	HFFUSE_RELEASE		= 18,
	HFFUSE_FSYNC		= 20,
	HFFUSE_SETXATTR		= 21,
	HFFUSE_GETXATTR		= 22,
	HFFUSE_LISTXATTR		= 23,
	HFFUSE_REMOVEXATTR	= 24,
	HFFUSE_FLUSH		= 25,
	HFFUSE_INIT		= 26,
	HFFUSE_OPENDIR		= 27,
	HFFUSE_READDIR		= 28,
	HFFUSE_RELEASEDIR		= 29,
	HFFUSE_FSYNCDIR		= 30,
	HFFUSE_GETLK		= 31,
	HFFUSE_SETLK		= 32,
	HFFUSE_SETLKW		= 33,
	HFFUSE_ACCESS		= 34,
	HFFUSE_CREATE		= 35,
	HFFUSE_INTERRUPT		= 36,
	HFFUSE_BMAP		= 37,
	HFFUSE_DESTROY		= 38,
	HFFUSE_IOCTL		= 39,
	HFFUSE_POLL		= 40,
	HFFUSE_NOTIFY_REPLY	= 41,
	HFFUSE_BATCH_FORGET	= 42,
	HFFUSE_FALLOCATE		= 43,
	HFFUSE_READDIRPLUS	= 44,
	HFFUSE_RENAME2		= 45,
	HFFUSE_LSEEK		= 46,
	HFFUSE_COPY_FILE_RANGE	= 47,
	HFFUSE_SETUPMAPPING	= 48,
	HFFUSE_REMOVEMAPPING	= 49,
	HFFUSE_SYNCFS		= 50,
	HFFUSE_TMPFILE		= 51,
	HFFUSE_STATX		= 52,

	/* CUSE specific operations */
	CUSE_INIT		= 4096,

	/* Reserved opcodes: helpful to detect structure endian-ness */
	CUSE_INIT_BSWAP_RESERVED	= 1048576,	/* CUSE_INIT << 8 */
	HFFUSE_INIT_BSWAP_RESERVED	= 436207616,	/* HFFUSE_INIT << 24 */
};

enum hffuse_notify_code {
	HFFUSE_NOTIFY_POLL   = 1,
	HFFUSE_NOTIFY_INVAL_INODE = 2,
	HFFUSE_NOTIFY_INVAL_ENTRY = 3,
	HFFUSE_NOTIFY_STORE = 4,
	HFFUSE_NOTIFY_RETRIEVE = 5,
	HFFUSE_NOTIFY_DELETE = 6,
	HFFUSE_NOTIFY_CODE_MAX,
};

/* The read buffer is required to be at least 8k, but may be much larger */
#define HFFUSE_MIN_READ_BUFFER 8192

#define HFFUSE_COMPAT_ENTRY_OUT_SIZE 120

struct hffuse_entry_out {
	uint64_t	nodeid;		/* Inode ID */
	uint64_t	generation;	/* Inode generation: nodeid:gen must
					   be unique for the fs's lifetime */
	uint64_t	entry_valid;	/* Cache timeout for the name */
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	entry_valid_nsec;
	uint32_t	attr_valid_nsec;
	struct hffuse_attr attr;
};

struct hffuse_forget_in {
	uint64_t	nlookup;
};

struct hffuse_forget_one {
	uint64_t	nodeid;
	uint64_t	nlookup;
};

struct hffuse_batch_forget_in {
	uint32_t	count;
	uint32_t	dummy;
};

struct hffuse_getattr_in {
	uint32_t	getattr_flags;
	uint32_t	dummy;
	uint64_t	fh;
};

#define HFFUSE_COMPAT_ATTR_OUT_SIZE 96

struct hffuse_attr_out {
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	attr_valid_nsec;
	uint32_t	dummy;
	struct hffuse_attr attr;
};

struct hffuse_statx_in {
	uint32_t	getattr_flags;
	uint32_t	reserved;
	uint64_t	fh;
	uint32_t	sx_flags;
	uint32_t	sx_mask;
};

struct hffuse_statx_out {
	uint64_t	attr_valid;	/* Cache timeout for the attributes */
	uint32_t	attr_valid_nsec;
	uint32_t	flags;
	uint64_t	spare[2];
	struct hffuse_statx stat;
};

#define HFFUSE_COMPAT_MKNOD_IN_SIZE 8

struct hffuse_mknod_in {
	uint32_t	mode;
	uint32_t	rdev;
	uint32_t	umask;
	uint32_t	padding;
};

struct hffuse_mkdir_in {
	uint32_t	mode;
	uint32_t	umask;
};

struct hffuse_rename_in {
	uint64_t	newdir;
};

struct hffuse_rename2_in {
	uint64_t	newdir;
	uint32_t	flags;
	uint32_t	padding;
};

struct hffuse_link_in {
	uint64_t	oldnodeid;
};

struct hffuse_setattr_in {
	uint32_t	valid;
	uint32_t	padding;
	uint64_t	fh;
	uint64_t	size;
	uint64_t	lock_owner;
	uint64_t	atime;
	uint64_t	mtime;
	uint64_t	ctime;
	uint32_t	atimensec;
	uint32_t	mtimensec;
	uint32_t	ctimensec;
	uint32_t	mode;
	uint32_t	unused4;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	unused5;
};

struct hffuse_open_in {
	uint32_t	flags;
	uint32_t	open_flags;	/* HFFUSE_OPEN_... */
};

struct hffuse_create_in {
	uint32_t	flags;
	uint32_t	mode;
	uint32_t	umask;
	uint32_t	open_flags;	/* HFFUSE_OPEN_... */
};

struct hffuse_open_out {
	uint64_t	fh;
	uint32_t	open_flags;
	uint32_t	padding;
};

struct hffuse_release_in {
	uint64_t	fh;
	uint32_t	flags;
	uint32_t	release_flags;
	uint64_t	lock_owner;
};

struct hffuse_flush_in {
	uint64_t	fh;
	uint32_t	unused;
	uint32_t	padding;
	uint64_t	lock_owner;
};

struct hffuse_read_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	read_flags;
	uint64_t	lock_owner;
	uint32_t	flags;
	uint32_t	padding;
};

#define HFFUSE_COMPAT_WRITE_IN_SIZE 24

struct hffuse_write_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	write_flags;
	uint64_t	lock_owner;
	uint32_t	flags;
	uint32_t	padding;
};

struct hffuse_write_out {
	uint32_t	size;
	uint32_t	padding;
};

#define HFFUSE_COMPAT_STATFS_SIZE 48

struct hffuse_statfs_out {
	struct hffuse_kstatfs st;
};

struct hffuse_fsync_in {
	uint64_t	fh;
	uint32_t	fsync_flags;
	uint32_t	padding;
};

#define HFFUSE_COMPAT_SETXATTR_IN_SIZE 8

struct hffuse_setxattr_in {
	uint32_t	size;
	uint32_t	flags;
	uint32_t	setxattr_flags;
	uint32_t	padding;
};

struct hffuse_getxattr_in {
	uint32_t	size;
	uint32_t	padding;
};

struct hffuse_getxattr_out {
	uint32_t	size;
	uint32_t	padding;
};

struct hffuse_lk_in {
	uint64_t	fh;
	uint64_t	owner;
	struct hffuse_file_lock lk;
	uint32_t	lk_flags;
	uint32_t	padding;
};

struct hffuse_lk_out {
	struct hffuse_file_lock lk;
};

struct hffuse_access_in {
	uint32_t	mask;
	uint32_t	padding;
};

struct hffuse_init_in {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	uint32_t	flags2;
	uint32_t	unused[11];
};

#define HFFUSE_COMPAT_INIT_OUT_SIZE 8
#define HFFUSE_COMPAT_22_INIT_OUT_SIZE 24

struct hffuse_init_out {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	uint16_t	max_background;
	uint16_t	congestion_threshold;
	uint32_t	max_write;
	uint32_t	time_gran;
	uint16_t	max_pages;
	uint16_t	map_alignment;
	uint32_t	flags2;
	uint32_t	unused[7];
};

#define CUSE_INIT_INFO_MAX 4096

struct cuse_init_in {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	unused;
	uint32_t	flags;
};

struct cuse_init_out {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	unused;
	uint32_t	flags;
	uint32_t	max_read;
	uint32_t	max_write;
	uint32_t	dev_major;		/* chardev major */
	uint32_t	dev_minor;		/* chardev minor */
	uint32_t	spare[10];
};

struct hffuse_interrupt_in {
	uint64_t	unique;
};

struct hffuse_bmap_in {
	uint64_t	block;
	uint32_t	blocksize;
	uint32_t	padding;
};

struct hffuse_bmap_out {
	uint64_t	block;
};

struct hffuse_ioctl_in {
	uint64_t	fh;
	uint32_t	flags;
	uint32_t	cmd;
	uint64_t	arg;
	uint32_t	in_size;
	uint32_t	out_size;
};

struct hffuse_ioctl_iovec {
	uint64_t	base;
	uint64_t	len;
};

struct hffuse_ioctl_out {
	int32_t		result;
	uint32_t	flags;
	uint32_t	in_iovs;
	uint32_t	out_iovs;
};

struct hffuse_poll_in {
	uint64_t	fh;
	uint64_t	kh;
	uint32_t	flags;
	uint32_t	events;
};

struct hffuse_poll_out {
	uint32_t	revents;
	uint32_t	padding;
};

struct hffuse_notify_poll_wakeup_out {
	uint64_t	kh;
};

struct hffuse_fallocate_in {
	uint64_t	fh;
	uint64_t	offset;
	uint64_t	length;
	uint32_t	mode;
	uint32_t	padding;
};

struct hffuse_in_header {
	uint32_t	len;
	uint32_t	opcode;
	uint64_t	unique;
	uint64_t	nodeid;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	pid;
	uint16_t	total_extlen; /* length of extensions in 8byte units */
	uint16_t	padding;
};

struct hffuse_out_header {
	uint32_t	len;
	int32_t		error;
	uint64_t	unique;
};

struct hffuse_dirent {
	uint64_t	ino;
	uint64_t	off;
	uint32_t	namelen;
	uint32_t	type;
	char name[];
};

/* Align variable length records to 64bit boundary */
#define HFFUSE_REC_ALIGN(x) \
	(((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))

#define HFFUSE_NAME_OFFSET offsetof(struct hffuse_dirent, name)
#define HFFUSE_DIRENT_ALIGN(x) HFFUSE_REC_ALIGN(x)
#define HFFUSE_DIRENT_SIZE(d) \
	HFFUSE_DIRENT_ALIGN(HFFUSE_NAME_OFFSET + (d)->namelen)

struct hffuse_direntplus {
	struct hffuse_entry_out entry_out;
	struct hffuse_dirent dirent;
};

#define HFFUSE_NAME_OFFSET_DIRENTPLUS \
	offsetof(struct hffuse_direntplus, dirent.name)
#define HFFUSE_DIRENTPLUS_SIZE(d) \
	HFFUSE_DIRENT_ALIGN(HFFUSE_NAME_OFFSET_DIRENTPLUS + (d)->dirent.namelen)

struct hffuse_notify_inval_inode_out {
	uint64_t	ino;
	int64_t		off;
	int64_t		len;
};

struct hffuse_notify_inval_entry_out {
	uint64_t	parent;
	uint32_t	namelen;
	uint32_t	flags;
};

struct hffuse_notify_delete_out {
	uint64_t	parent;
	uint64_t	child;
	uint32_t	namelen;
	uint32_t	padding;
};

struct hffuse_notify_store_out {
	uint64_t	nodeid;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	padding;
};

struct hffuse_notify_retrieve_out {
	uint64_t	notify_unique;
	uint64_t	nodeid;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	padding;
};

/* Matches the size of hffuse_write_in */
struct hffuse_notify_retrieve_in {
	uint64_t	dummy1;
	uint64_t	offset;
	uint32_t	size;
	uint32_t	dummy2;
	uint64_t	dummy3;
	uint64_t	dummy4;
};

/* Device ioctls: */
#define HFFUSE_DEV_IOC_MAGIC		229
#define HFFUSE_DEV_IOC_CLONE		_IOR(HFFUSE_DEV_IOC_MAGIC, 0, uint32_t)

struct hffuse_lseek_in {
	uint64_t	fh;
	uint64_t	offset;
	uint32_t	whence;
	uint32_t	padding;
};

struct hffuse_lseek_out {
	uint64_t	offset;
};

struct hffuse_copy_file_range_in {
	uint64_t	fh_in;
	uint64_t	off_in;
	uint64_t	nodeid_out;
	uint64_t	fh_out;
	uint64_t	off_out;
	uint64_t	len;
	uint64_t	flags;
};

#define HFFUSE_SETUPMAPPING_FLAG_WRITE (1ull << 0)
#define HFFUSE_SETUPMAPPING_FLAG_READ (1ull << 1)
struct hffuse_setupmapping_in {
	/* An already open handle */
	uint64_t	fh;
	/* Offset into the file to start the mapping */
	uint64_t	foffset;
	/* Length of mapping required */
	uint64_t	len;
	/* Flags, HFFUSE_SETUPMAPPING_FLAG_* */
	uint64_t	flags;
	/* Offset in Memory Window */
	uint64_t	moffset;
};

struct hffuse_removemapping_in {
	/* number of hffuse_removemapping_one follows */
	uint32_t        count;
};

struct hffuse_removemapping_one {
	/* Offset into the dax window start the unmapping */
	uint64_t        moffset;
	/* Length of mapping required */
	uint64_t	len;
};

#define HFFUSE_REMOVEMAPPING_MAX_ENTRY   \
		(PAGE_SIZE / sizeof(struct hffuse_removemapping_one))

struct hffuse_syncfs_in {
	uint64_t	padding;
};

/*
 * For each security context, send hffuse_secctx with size of security context
 * hffuse_secctx will be followed by security context name and this in turn
 * will be followed by actual context label.
 * hffuse_secctx, name, context
 */
struct hffuse_secctx {
	uint32_t	size;
	uint32_t	padding;
};

/*
 * Contains the information about how many hffuse_secctx structures are being
 * sent and what's the total size of all security contexts (including
 * size of hffuse_secctx_header).
 *
 */
struct hffuse_secctx_header {
	uint32_t	size;
	uint32_t	nr_secctx;
};

/**
 * struct hffuse_ext_header - extension header
 * @size: total size of this extension including this header
 * @type: type of extension
 *
 * This is made compatible with hffuse_secctx_header by using type values >
 * HFFUSE_MAX_NR_SECCTX
 */
struct hffuse_ext_header {
	uint32_t	size;
	uint32_t	type;
};

/**
 * struct hffuse_supp_groups - Supplementary group extension
 * @nr_groups: number of supplementary groups
 * @groups: flexible array of group IDs
 */
struct hffuse_supp_groups {
	uint32_t	nr_groups;
	uint32_t	groups[];
};

#define HFFUSE_MINOR 251

#endif /* _LINUX_HFFUSE_H */
