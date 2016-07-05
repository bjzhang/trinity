# Makefile

#export these variables to make sure the Makefile can use them
export sourcepath   ?= $(shell pwd)
export sourcefile   ?= $(notdir $(shell ls *.c |grep -v kmemleak-page.c ))
export objs         := $(patsubst %.c,%.o,$(sourcefile))

#KERNEL_DIR     :=/home/cuibixuan/linux-3.10-cma
#ARCH	:=x86_64

KERNEL_DIR     :=/home/cuibixuan/hulk.qemu
CROSS_COMPILE  :=/home/cuibixuan/install_be/install/bin/aarch64_be-linux-gnu-
ARCH   :=arm64

#KERNEL_DIR     :=/home/cuibixuan/hulk.3.3.7
#CROSS_COMPILE  :=/home/cuibixuan/install/install/bin/aarch64-linux-gnu-
#ARCH   :=arm64

ifneq ($(KERNELRELEASE),)
        obj-m += $(objs)
else
default:
	$(MAKE) -C $(KERNEL_DIR) CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(ARCH)  M=$(sourcepath) modules
clean:
	rm -rf kmemleak-page  *.o *.mod.c *.mod.o *.ko .*.mod .*.cmd .tmp_versions modules.order Module.symvers
endif
