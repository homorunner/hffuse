/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM hffuse

#if !defined(_TRACE_HFFUSE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HFFUSE_H

#include <linux/tracepoint.h>

#define OPCODES							\
	EM( HFFUSE_LOOKUP,		"HFFUSE_LOOKUP")		\
	EM( HFFUSE_FORGET,		"HFFUSE_FORGET")		\
	EM( HFFUSE_GETATTR,		"HFFUSE_GETATTR")		\
	EM( HFFUSE_SETATTR,		"HFFUSE_SETATTR")		\
	EM( HFFUSE_READLINK,		"HFFUSE_READLINK")	\
	EM( HFFUSE_SYMLINK,		"HFFUSE_SYMLINK")		\
	EM( HFFUSE_MKNOD,			"HFFUSE_MKNOD")		\
	EM( HFFUSE_MKDIR,			"HFFUSE_MKDIR")		\
	EM( HFFUSE_UNLINK,		"HFFUSE_UNLINK")		\
	EM( HFFUSE_RMDIR,			"HFFUSE_RMDIR")		\
	EM( HFFUSE_RENAME,		"HFFUSE_RENAME")		\
	EM( HFFUSE_LINK,			"HFFUSE_LINK")		\
	EM( HFFUSE_OPEN,			"HFFUSE_OPEN")		\
	EM( HFFUSE_READ,			"HFFUSE_READ")		\
	EM( HFFUSE_WRITE,			"HFFUSE_WRITE")		\
	EM( HFFUSE_STATFS,		"HFFUSE_STATFS")		\
	EM( HFFUSE_RELEASE,		"HFFUSE_RELEASE")		\
	EM( HFFUSE_FSYNC,			"HFFUSE_FSYNC")		\
	EM( HFFUSE_SETXATTR,		"HFFUSE_SETXATTR")	\
	EM( HFFUSE_GETXATTR,		"HFFUSE_GETXATTR")	\
	EM( HFFUSE_LISTXATTR,		"HFFUSE_LISTXATTR")	\
	EM( HFFUSE_REMOVEXATTR,		"HFFUSE_REMOVEXATTR")	\
	EM( HFFUSE_FLUSH,			"HFFUSE_FLUSH")		\
	EM( HFFUSE_INIT,			"HFFUSE_INIT")		\
	EM( HFFUSE_OPENDIR,		"HFFUSE_OPENDIR")		\
	EM( HFFUSE_READDIR,		"HFFUSE_READDIR")		\
	EM( HFFUSE_RELEASEDIR,		"HFFUSE_RELEASEDIR")	\
	EM( HFFUSE_FSYNCDIR,		"HFFUSE_FSYNCDIR")	\
	EM( HFFUSE_GETLK,			"HFFUSE_GETLK")		\
	EM( HFFUSE_SETLK,			"HFFUSE_SETLK")		\
	EM( HFFUSE_SETLKW,		"HFFUSE_SETLKW")		\
	EM( HFFUSE_ACCESS,		"HFFUSE_ACCESS")		\
	EM( HFFUSE_CREATE,		"HFFUSE_CREATE")		\
	EM( HFFUSE_INTERRUPT,		"HFFUSE_INTERRUPT")	\
	EM( HFFUSE_BMAP,			"HFFUSE_BMAP")		\
	EM( HFFUSE_DESTROY,		"HFFUSE_DESTROY")		\
	EM( HFFUSE_IOCTL,			"HFFUSE_IOCTL")		\
	EM( HFFUSE_POLL,			"HFFUSE_POLL")		\
	EM( HFFUSE_NOTIFY_REPLY,		"HFFUSE_NOTIFY_REPLY")	\
	EM( HFFUSE_BATCH_FORGET,		"HFFUSE_BATCH_FORGET")	\
	EM( HFFUSE_FALLOCATE,		"HFFUSE_FALLOCATE")	\
	EM( HFFUSE_READDIRPLUS,		"HFFUSE_READDIRPLUS")	\
	EM( HFFUSE_RENAME2,		"HFFUSE_RENAME2")		\
	EM( HFFUSE_LSEEK,			"HFFUSE_LSEEK")		\
	EM( HFFUSE_COPY_FILE_RANGE,	"HFFUSE_COPY_FILE_RANGE")	\
	EM( HFFUSE_SETUPMAPPING,		"HFFUSE_SETUPMAPPING")	\
	EM( HFFUSE_REMOVEMAPPING,		"HFFUSE_REMOVEMAPPING")	\
	EM( HFFUSE_SYNCFS,		"HFFUSE_SYNCFS")		\
	EM( HFFUSE_TMPFILE,		"HFFUSE_TMPFILE")		\
	EM( HFFUSE_STATX,			"HFFUSE_STATX")		\
	EMe(CUSE_INIT,			"CUSE_INIT")

/*
 * This will turn the above table into TRACE_DEFINE_ENUM() for each of the
 * entries.
 */
#undef EM
#undef EMe
#define EM(a, b)	TRACE_DEFINE_ENUM(a);
#define EMe(a, b)	TRACE_DEFINE_ENUM(a);

OPCODES

/* Now we redfine it with the table that __print_symbolic needs. */
#undef EM
#undef EMe
#define EM(a, b)	{a, b},
#define EMe(a, b)	{a, b}

TRACE_EVENT(hffuse_request_send,
	TP_PROTO(const struct hffuse_req *req),

	TP_ARGS(req),

	TP_STRUCT__entry(
		__field(dev_t,			connection)
		__field(uint64_t,		unique)
		__field(enum hffuse_opcode,	opcode)
		__field(uint32_t,		len)
	),

	TP_fast_assign(
		__entry->connection	=	req->fm->fc->dev;
		__entry->unique		=	req->in.h.unique;
		__entry->opcode		=	req->in.h.opcode;
		__entry->len		=	req->in.h.len;
	),

	TP_printk("connection %u req %llu opcode %u (%s) len %u ",
		  __entry->connection, __entry->unique, __entry->opcode,
		  __print_symbolic(__entry->opcode, OPCODES), __entry->len)
);

TRACE_EVENT(hffuse_request_end,
	TP_PROTO(const struct hffuse_req *req),

	TP_ARGS(req),

	TP_STRUCT__entry(
		__field(dev_t,		connection)
		__field(uint64_t,	unique)
		__field(uint32_t,	len)
		__field(int32_t,	error)
	),

	TP_fast_assign(
		__entry->connection	=	req->fm->fc->dev;
		__entry->unique		=	req->in.h.unique;
		__entry->len		=	req->out.h.len;
		__entry->error		=	req->out.h.error;
	),

	TP_printk("connection %u req %llu len %u error %d", __entry->connection,
		  __entry->unique, __entry->len, __entry->error)
);

#endif /* _TRACE_HFFUSE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE hffuse_trace
#include <trace/define_trace.h>
