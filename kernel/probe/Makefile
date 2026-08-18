# SPDX-License-Identifier: GPL-2.0
#
# Driver for the out-of-tree probe module. Nothing here loads anything: the
# module is only ever loaded on the kernel it was built against, which is the
# guest the harness boots.
#
# KDIR names that kernel's build tree; the three VOIDPORT_* variables named in
# Kbuild carry the crate sources. The nix expressions beside this directory set
# all four.

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all crates clean

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

# The wire crate alone, under the same kbuild flags the module is built with.
# It is a rung of its own on the ladder because a crate that stops riding
# kbuild is a different failure from a module that stops building.
crates:
	$(MAKE) -C $(KDIR) M=$(CURDIR) voidport_proto.o

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
