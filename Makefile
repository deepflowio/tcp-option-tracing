ifneq ($(KERNELRELEASE),)

obj-m := tot.o
ccflags-y += -I$(src)

ifeq ($(DISABLE_SAMPLING), true)
ccflags-y += -DDISABLE_SAMPLING
endif

ifeq ($(DISABLE_TCPSEQ), true)
ccflags-y += -DDISABLE_TCPSEQ
endif

else

KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

endif 
