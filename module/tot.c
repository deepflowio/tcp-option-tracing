/**
 * TCP Option Tracing
 */
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <net/ip.h>

MODULE_LICENSE("GPL v2");

#define TCP_OPTION_TRACING_CODE 253
#define TCP_OPTION_TRACING_MAGIC 0xDEE9

// 0        1        2        3
// 01234567 89012345 67890123 45678901
// +--------+--------+--------+--------+
// |  Kind  | Length |       ExID      |
// +--------+--------+--------+--------+
// |                Pid                |
// +--------+--------+--------+--------+
// |           Source Address          |
// +--------+--------+--------+--------+
// |              TCP SEQ              |
// +--------+--------+--------+--------+
//
// https://datatracker.ietf.org/doc/rfc6994/
// https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-exids

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
#error "Please update your kernel"
#endif

#if defined(DISABLE_SAMPLING)
static bool is_cover_rounded_up_seq(struct sk_buff *skb)
{
	return true;
}
#else
static bool is_cover_rounded_up_seq(struct sk_buff *skb)
{
	unsigned int seq = ntohl(tcp_hdr(skb)->seq);
	unsigned int len = skb->len - ip_hdrlen(skb) - tcp_hdrlen(skb);
	unsigned int rounded_up_seq = seq | 0x3FFFU;
	return rounded_up_seq < seq + len;
}
#endif

// Centos7 modified the function signature without updating the kernel version
// number. Currently, there should be no other version 3.10 kernel running
// except CentOS 7
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0)
static unsigned int add_tcp_option_tracing(const struct nf_hook_ops *ops, struct sk_buff *skb,
					   const struct net_device *in, const struct net_device *out,
					   const struct nf_hook_state *state)

// https://github.com/torvalds/linux/commit/238e54c9cb9385a1ba99e92801f3615a2fb398b6
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static unsigned int add_tcp_option_tracing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)

// https://github.com/torvalds/linux/commit/795aa6ef6a1aba99050735eadd0c2341b789b53b
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
static unsigned int add_tcp_option_tracing(const struct nf_hook_ops *ops, struct sk_buff *skb,
					   const struct net_device *in, const struct net_device *out,
					   int (*okfn)(struct sk_buff *))

// https://github.com/torvalds/linux/commit/3db05fea51cdb162cfa8f69e9cfb9e228919d2a9
#else
static unsigned int add_tcp_option_tracing(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
					   const struct net_device *out, int (*okfn)(struct sk_buff *))
#endif
{
	struct tcp_option_tracing *tot = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	u8 *p = NULL, *q = NULL;
	u32 mtu = 0;
	int ntail = 0;
	unsigned int tcphoff = 0;

	/* now only process TCP syn/synack/push */
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		goto out;

	tcph = tcp_hdr(skb);
	if (!tcph->psh && !tcph->syn)
		goto out;

	/* modify a push packet when every 16KB of data are delivered. */
	if (tcph->psh && !is_cover_rounded_up_seq(skb))
		goto out;

	/* skb length and tcp option length checking */
	mtu = dst_mtu(skb_dst(skb));
	if (mtu < skb->len + sizeof(struct tcp_option_tracing))
		goto out;

	/* the maximum length of TCP head is 60 bytes, so only 40 bytes for options */
	if ((60 - (tcph->doff * 4)) < sizeof(struct tcp_option_tracing))
		goto out;

	if (unlikely(skb_linearize(skb) != 0))
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	/* csum_check requires unshared skb */
	if (skb_ensure_writable(skb, ip_hdrlen(skb) + sizeof(*tcph)))
		goto out;
#else
	if (!skb_make_writable(skb, ip_hdrlen(skb) + sizeof(*tcph)))
		goto out;
#endif

	/* expand skb if needed */
	if (sizeof(struct tcp_option_tracing) > skb_tailroom(skb)) {
		ntail = sizeof(struct tcp_option_tracing);
		if (pskb_expand_head(skb, 0, ntail, GFP_ATOMIC)) {
			goto out;
		}
	}

	/* get new tcp/ip header */
	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);
	tcphoff = ip_hdrlen(skb);

	/* ptr to old opts */
	p = skb_tail_pointer(skb) - 1;
	q = p + sizeof(struct tcp_option_tracing);

	/* move data down, offset is sizeof(struct tcp_option_tracing) */
	while (p >= ((u8 *)tcph + sizeof(struct tcphdr)))
		*q-- = *p--;

	/* move tail to new postion */
	skb->tail += sizeof(struct tcp_option_tracing);

	/* put tracing opt , ptr point to opts */
	tot = (struct tcp_option_tracing *)(tcph + 1);
	tot->opcode = TCP_OPTION_TRACING_CODE;
	tot->opsize = sizeof(struct tcp_option_tracing);
	tot->magic = htons(TCP_OPTION_TRACING_MAGIC);
	tot->pid = htonl(current->tgid);
#if !defined(DISABLE_SADDR)
	tot->saddr = iph->saddr;
#endif
#if !defined(DISABLE_TCPSEQ)
	tot->seq = tcph->seq;
#endif

	/* reset tcp header length */
	tcph->doff += sizeof(struct tcp_option_tracing) / 4;
	/* reset ip header totoal length */
	iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(struct tcp_option_tracing));
	/* reset skb length */
	skb->len += sizeof(struct tcp_option_tracing);

	/* re-calculate tcp csum */
	tcph->check = 0;
	skb->csum = skb_checksum(skb, tcphoff, skb->len - tcphoff, 0);
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - tcphoff, iph->protocol, skb->csum);

	/* re-calculate ip head csum, tot_len has been adjusted */
	ip_send_check(ip_hdr(skb));

	skb->ip_summed = CHECKSUM_UNNECESSARY;
out:
	return NF_ACCEPT;
}

static struct nf_hook_ops tcp_option_tracing_ops = {
	.hook = add_tcp_option_tracing,
	.pf = PF_INET, // IPv4 only
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
};

static int tot_init(void)
{
// https://github.com/torvalds/linux/commit/085db2c04557d31db61541f361bd8b4de92c9939
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct net *net;
	for_each_net (net) {
		if (nf_register_net_hook(net, &tcp_option_tracing_ops)) {
			printk(KERN_ERR "tot: nf_register_net_hook failed");
		}
	}
#else
	if (nf_register_hook(&tcp_option_tracing_ops)) {
		printk(KERN_ERR "tot: nf_register_hook failed");
	}
#endif
	return 0;
}

static void tot_exit(void)
{
// https://github.com/torvalds/linux/commit/085db2c04557d31db61541f361bd8b4de92c9939
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	struct net *net;
	for_each_net (net) {
		nf_unregister_net_hook(net, &tcp_option_tracing_ops);
	}
#else
	nf_unregister_hook(&tcp_option_tracing_ops);
#endif
	return;
}

module_init(tot_init);
module_exit(tot_exit);
