#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "fw_xdp.skel.h"

static volatile sig_atomic_t parar;
static void sai(int s) { parar = 1; }

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "uso: %s <interface> [ip_a_bloquear]\n", argv[0]);
        return 1;
    }
    int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    struct fw_xdp_bpf *skel = fw_xdp_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "falha ao carregar o programa\n"); return 1; }

    if (argc > 2) {
        struct in_addr a;
        __u32 v = 1;
        if (inet_pton(AF_INET, argv[2], &a) != 1) { fprintf(stderr, "IP invalido\n"); return 1; }
        /* a.s_addr ja esta em ordem de rede, como no pacote */
        bpf_map_update_elem(bpf_map__fd(skel->maps.blocklist), &a.s_addr, &v, BPF_ANY);
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_fw, ifindex);
    if (!link) { fprintf(stderr, "falha ao anexar o XDP\n"); return 1; }

    signal(SIGINT, sai);
    int ncpu = libbpf_num_possible_cpus();
    __u64 *vals = calloc(ncpu, sizeof(__u64));
    while (!parar) {
        sleep(1);
        for (__u32 k = 0; k < 2; k++) {
            __u64 soma = 0;
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &k, vals) == 0)
                for (int i = 0; i < ncpu; i++)
                    soma += vals[i];
            printf("%s=%llu ", k ? "descartados" : "aceitos", (unsigned long long)soma);
        }
        printf("\n");
    }
    bpf_link__destroy(link);
    fw_xdp_bpf__destroy(skel);
    return 0;
}
