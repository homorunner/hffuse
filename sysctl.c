// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/hffuse/hffuse_sysctl.c
 *
 * Sysctl interface to hffuse parameters
 */
#include <linux/sysctl.h>

#include "hffuse_i.h"

static struct ctl_table_header *hffuse_table_header;

/* Bound by hffuse_init_out max_pages, which is a u16 */
static unsigned int sysctl_hffuse_max_pages_limit = 65535;

static const struct ctl_table hffuse_sysctl_table[] = {
	{
		.procname	= "max_pages_limit",
		.data		= &hffuse_max_pages_limit,
		.maxlen		= sizeof(hffuse_max_pages_limit),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= &sysctl_hffuse_max_pages_limit,
	},
};

int hffuse_sysctl_register(void)
{
	hffuse_table_header = register_sysctl("fs/hffuse", hffuse_sysctl_table);
	if (!hffuse_table_header)
		return -ENOMEM;
	return 0;
}

void hffuse_sysctl_unregister(void)
{
	unregister_sysctl_table(hffuse_table_header);
	hffuse_table_header = NULL;
}
