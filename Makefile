# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the HFFUSE filesystem.
#

# obj-$(CONFIG_HFFUSE_FS) += hffuse.o
# obj-$(CONFIG_CUSE) += cuse.o
# obj-$(CONFIG_VIRTIO_FS) += virtiofs.o

# hffuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o
# hffuse-$(CONFIG_HFFUSE_DAX) += dax.o

# virtiofs-y := virtio_fs.o

ccflags-y += -I$(PWD)

obj-m += hffuse.o

hffuse-objs := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o iomode.o sysctl.o

all:
	echo $(PWD)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

