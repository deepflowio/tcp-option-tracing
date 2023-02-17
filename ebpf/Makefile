CLANG ?= clang
CLANGXX ?= clang++

ifeq ($(DISABLE_SAMPLING), true)
CFLAG += -DDISABLE_SAMPLING
endif

ifeq ($(DISABLE_TCPSEQ), true)
CFLAG += -DDISABLE_TCPSEQ
endif

ifeq ($(DISABLE_SADDR), true)
CFLAG += -DDISABLE_SADDR
endif

tot: tot.skel.h tot.cc
	${CLANGXX} -static tot.cc -lbpf -lelf -lz -o tot

tot.skel.h: tot.bpf.o
	@bpftool version > /dev/null
	bpftool gen skeleton tot.bpf.o > tot.skel.h

tot.bpf.o: tot.bpf.c vmlinux.h
	${CLANG} ${CFLAG} -g -O2 -I . -target bpf -c tot.bpf.c -o tot.bpf.o
	
vmlinux.h:
	@bpftool version > /dev/null
	@ls /sys/kernel/btf/vmlinux > /dev/null
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm vmlinux.h tot.bpf.o tot.skel.h tot

.PHONY: clean
