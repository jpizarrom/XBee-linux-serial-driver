MODNAME ?= openthread-rcp
TARGET := $(MODNAME).ko
obj-m := $(MODNAME).o
openthread-rcp-objs := rcp_common.o ttyrcp.o spinel.o

ifeq (,$(KERNELRELEASE))
KVERS_UNAME ?= $(shell uname -r)
else
KVERS_UNAME ?= $(KERNELRELEASE)
endif

XBEE802154_DIR := kernel/drivers/net/ieee802154
KBUILD ?= $(shell readlink -f /lib/modules/$(KVERS_UNAME)/build)

ifeq (,$(KBUILD))
$(error Kernel build tree not found - please set KBUILD to configured kernel)
endif

KCONFIG := $(KBUILD)/.config
ifeq (,$(wildcard $(KCONFIG)))
$(error No .config found in $(KBUILD), please set KBUILD to configured kernel)
endif

ifneq (,$(wildcard $(KBUILD)/include/linux/version.h))
ifneq (,$(wildcard $(KBUILD)/include/generated/uapi/linux/version.h))
$(error Multiple copies of version.h found, please clean your build tree)
endif
endif

# Kernel Makefile doesn't always know the exact kernel version, so we
# get it from the kernel headers instead and pass it to make.
VERSION_H := $(KBUILD)/include/generated/utsrelease.h
ifeq (,$(wildcard $(VERSION_H)))
VERSION_H := $(KBUILD)/include/linux/utsrelease.h
endif
ifeq (,$(wildcard $(VERSION_H)))
VERSION_H := $(KBUILD)/include/linux/version.h
endif
ifeq (,$(wildcard $(VERSION_H)))
$(error Please run 'make modules_prepare' in $(KBUILD))
endif

KVERS := $(shell sed -ne 's/"//g;s/^\#define UTS_RELEASE //p' $(VERSION_H))

ifeq (,$(KVERS))
$(error Cannot find UTS_RELEASE in $(VERSION_H), please report)
endif

INST_DIR = /lib/modules/$(KVERS)/$(XBEE802154_DIR)

SRC_DIR=$(shell pwd)

include $(KCONFIG)

ifneq (,$(DEBUG))
EXTRA_CFLAGS += -DDEBUG
endif

EXTRA_CFLAGS += -Wformat=2 -Wall -Wunused-result

ifneq ($(MODTEST_ENABLE),)
EXTRA_CFLAGS += -DMODTEST_ENABLE=$(MODTEST_ENABLE)
endif

all: modules

modules:
	$(MAKE) -C $(KBUILD) M=$(SRC_DIR) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(SRC_DIR) clean

$(TARGET): modules

install: $(TARGET)
	@/sbin/modinfo $(TARGET) | grep -q "^vermagic: *$(KVERS) " || \
		{ echo "$(TARGET)" is not for Linux $(KVERS); exit 1; }
	mkdir -p -m 755 $(DESTDIR)$(INST_DIR)
	install -m 0644 $(TARGET) $(DESTDIR)$(INST_DIR)

