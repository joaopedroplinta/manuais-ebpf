#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int pkt_trace(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    bpf_printk("proto=%d src=%pI4 len=%d", ip->protocol, &ip->saddr,
               (int)(data_end - data));
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) <= data_end)
            bpf_printk("tcp %d -> %d syn=%d", bpf_ntohs(tcp->source),
                       bpf_ntohs(tcp->dest), tcp->syn);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
