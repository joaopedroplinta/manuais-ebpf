#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define JANELA_NS  1000000000ULL   /* janela de 1 s */
#define LIMITE_SYN 100             /* SYNs por origem por janela */

struct syn_info {
    __u64 inicio;   /* inicio da janela atual (ns) */
    __u64 syns;     /* SYNs vistos na janela */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);            /* IPv4 de origem */
    __type(value, struct syn_info);
} syn_por_origem SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);          /* total de SYNs descartados */
} descartados SEC(".maps");

SEC("xdp")
int syn_guard(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!(tcp->syn && !tcp->ack))      /* so SYN inicial */
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    struct syn_info *si = bpf_map_lookup_elem(&syn_por_origem, &src);

    if (!si) {
        struct syn_info novo = { .inicio = now, .syns = 1 };
        bpf_map_update_elem(&syn_por_origem, &src, &novo, BPF_ANY);
        return XDP_PASS;
    }
    if (now - si->inicio > JANELA_NS) {
        si->inicio = now;
        si->syns = 1;
        return XDP_PASS;
    }
    /* contagem nao atomica: aproximada com varias CPUs (suficiente aqui) */
    si->syns++;
    if (si->syns > LIMITE_SYN) {
        __u32 k = 0;
        __u64 *d = bpf_map_lookup_elem(&descartados, &k);
        if (d)
            __sync_fetch_and_add(d, 1);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
