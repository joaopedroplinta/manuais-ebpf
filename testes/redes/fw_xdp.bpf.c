#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);            /* IPv4 de origem (ordem de rede) */
    __type(value, __u32);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);            /* porta de destino (ordem do host) */
    __type(value, __u32);
} blocked_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);        /* 0 = aceitos, 1 = descartados */
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void conta(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        *v += 1;
}

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 1. origem na lista de bloqueio */
    __u32 src = ip->saddr;
    if (bpf_map_lookup_elem(&blocklist, &src))
        goto drop;

    /* 2. porta de destino bloqueada (TCP ou UDP) */
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        void *l4 = (void *)ip + ip->ihl * 4;
        struct udphdr *udp = l4;   /* dest fica no mesmo offset em TCP e UDP */
        if ((void *)(udp + 1) > data_end)
            goto ok;
        __u16 dport = bpf_ntohs(udp->dest);
        if (bpf_map_lookup_elem(&blocked_ports, &dport))
            goto drop;
    }

ok:
    conta(0);
    return XDP_PASS;
drop:
    conta(1);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
