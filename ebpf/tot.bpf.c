#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TCPHDR_SYN 0x02
#define TCPHDR_PSH 0x08
#define TCP_OPTION_TRACING_CODE 253
#define TCP_OPTION_TRACING_MAGIC 0xDEE9

struct __attribute__((packed)) tcp_option_tracing {
	u8 opcode;
	u8 opsize;
	u16 magic;
	u32 pid;

#if !defined(DISABLE_SADDR)
	u32 saddr;
#endif

#if !defined(DISABLE_TCPSEQ)
	u32 seq;
#endif
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, u64);
} percpu_syscall_proc_map SEC(".maps");

#if defined(DISABLE_SAMPLING)
static bool is_cover_rounded_up_seq(struct bpf_sock_ops *skops)
{
	return true;
}
#else
static bool is_cover_rounded_up_seq(struct bpf_sock_ops *skops)
{
	struct tcphdr *th = skops->skb_data;
	unsigned int seq = bpf_ntohl(BPF_CORE_READ(th, seq));
	unsigned int len = skops->skb_len;
	unsigned int rounded_up_seq = seq | 0x3FFFU;
	return rounded_up_seq < seq + len;
}
#endif

static u64 sockops_current_pid_tgid()
{
	int zero = 0;
	u64 *pid_tgid = bpf_map_lookup_elem(&percpu_syscall_proc_map, &zero);
	return pid_tgid ? *pid_tgid : 0;
}

static int syscall_pid_tgid_map_update(struct trace_event_raw_sys_enter *ctx)
{
	int key = 0;
	u64 value = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&percpu_syscall_proc_map, &key, &value, BPF_ANY);
	return 0;
}

static int syscall_pid_tgid_map_clear(struct trace_event_raw_sys_exit *ctx)
{
	int key = 0;
	u64 value = 0;
	bpf_map_update_elem(&percpu_syscall_proc_map, &key, &value, BPF_ANY);
	return 0;
}

static bool skops_can_add_option(struct bpf_sock_ops *skops)
{
	if (skops->skb_tcp_flags & TCPHDR_SYN)
		return true;

	if (!(skops->skb_tcp_flags & TCPHDR_PSH))
		return false;

	if (!is_cover_rounded_up_seq(skops))
		return false;

	if (skops->skb_len + sizeof(struct tcp_option_tracing) > skops->mss_cache)
		return false;

	return true;
}

static void sockops_set_hdr_cb_flags(struct bpf_sock_ops *skops)
{
	bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static void sockops_tcp_reserve_hdr(struct bpf_sock_ops *skops)
{
	if (!skops_can_add_option(skops))
		return;

	bpf_reserve_hdr_opt(skops, sizeof(struct tcp_option_tracing), 0);
}

static inline void sockops_tcp_store_hdr(struct bpf_sock_ops *skops)
{
	struct tcp_option_tracing tot;
	struct tcphdr *th = skops->skb_data;

	if (!skops_can_add_option(skops))
		return;

	tot.opcode = TCP_OPTION_TRACING_CODE;
	tot.opsize = sizeof(struct tcp_option_tracing);
	tot.magic = bpf_htons(TCP_OPTION_TRACING_MAGIC);
	tot.pid = bpf_htonl(sockops_current_pid_tgid() >> 32);

#if !defined(DISABLE_SADDR)
	tot.saddr = skops->local_ip4;
#endif

#if !defined(DISABLE_TCPSEQ)
	tot.seq = BPF_CORE_READ(th, seq);
#endif

	bpf_store_hdr_opt(skops, &tot, sizeof(tot), 0);
}

SEC("sockops")
int sockops_write_tcp_options(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		sockops_set_hdr_cb_flags(skops);
		break;
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		sockops_tcp_reserve_hdr(skops);
		break;
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		sockops_tcp_store_hdr(skops);
		break;
	}
	return 1;
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	return syscall_pid_tgid_map_update(ctx);
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	return syscall_pid_tgid_map_clear(ctx);
}
