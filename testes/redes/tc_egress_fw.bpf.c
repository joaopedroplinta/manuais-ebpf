#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);            /* porta TCP de destino proibida na saida */
    __type(value, __u64);          /* pacotes descartados */
} saida_proibida SEC(".maps");

SEC("tc")
int tc_egress_fw(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcp->dest);
    __u64 *n = bpf_map_lookup_elem(&saida_proibida, &dport);
    if (n) {
        __sync_fetch_and_add(n, 1);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
