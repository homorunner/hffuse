# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the HFFUSE filesystem.
#

# Needed for trace events
ccflags-y = -I$(src)

obj-$(CONFIG_HFFUSE_FS) += hffuse.o
obj-$(CONFIG_CUSE) += cuse.o
obj-$(CONFIG_VIRTIO_FS) += virtiofs.o

hffuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o
hffuse-y += iomode.o
hffuse-$(CONFIG_HFFUSE_DAX) += dax.o
hffuse-$(CONFIG_HFFUSE_PASSTHROUGH) += passthrough.o
hffuse-$(CONFIG_SYSCTL) += sysctl.o
hffuse-$(CONFIG_HFFUSE_IO_URING) += dev_uring.o

virtiofs-y := virtio_fs.o
