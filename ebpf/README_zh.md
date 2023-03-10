## 依赖

### 编译器

- clang/clang++ 11.0.1

### 静态库

- libbpf 0.3
- libelf 0.183
- libz 1.2.11

### 内核

- linux kernel 5.10 with CONFIG_DEBUG_INFO_BTF=y

## 构建镜像

```txt
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
docker build -t tot-ebpf .
docker run --ulimit memlock=503173 --rm --privileged --pid=host --net=host -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux -v /sys/fs/cgroup:/sys/fs/cgroup tot-ebpf
```
