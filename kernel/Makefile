# SPDX-License-Identifier: GPL-2.0
KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all modules fs-module crates wire-crate session-crate c-object clean

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

fs-module:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/voidport modules

crates: wire-crate session-crate

wire-crate:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/voidport voidport_proto.o

session-crate:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/voidport voidport_session.o

c-object:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/transport V=1 voidport_helpers.o

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
