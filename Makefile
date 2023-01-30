ifneq ($(KERNELRELEASE),)

obj-m := top.o
ccflags-y += -I$(src)

else

KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build
DRIVER_VERSION ?= "v0.0.1"

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

endif 
