#!/usr/bin/env bash
# Rodada 3: programa libbpf do cap. 5 (compilar, carregar, ler mapa) e exporter Python do cap. 7.
# Pre-requisito: sudo apt install -y clang llvm libbpf-dev libelf-dev python3-prometheus-client
# Rodar com: sudo bash testes/03-programa-libbpf-e-exporter.sh
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
for c in clang bpftool python3 curl; do command -v $c >/dev/null || { echo "FALTA $c"; exit 1; }; done
python3 -c 'import prometheus_client' 2>/dev/null || { echo "FALTA python3-prometheus-client"; exit 1; }

W=/tmp/ebpf-teste; rm -rf $W; mkdir -p $W; cd $W
ARCH=$(uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
cleanup() { kill $SRV $EXP 2>/dev/null; rm -rf /sys/fs/bpf/monitor; }
trap cleanup EXIT

echo "== 1. vmlinux.h"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h && wc -l vmlinux.h

echo "== 2. compilar monitor.bpf.c"
cat > monitor.bpf.c <<'EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);    /* porta TCP de destino */
    __type(value, __u64);  /* bytes acumulados */
} bytes_por_porta SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk,
               struct msghdr *msg, size_t size)
{
    __u16 porta = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    __u64 *total = bpf_map_lookup_elem(&bytes_por_porta, &porta);

    if (total) {
        __sync_fetch_and_add(total, size);
    } else {
        __u64 inicial = size;
        bpf_map_update_elem(&bytes_por_porta, &porta, &inicial, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -D__TARGET_ARCH_$ARCH -I . -c monitor.bpf.c -o monitor.bpf.o 2>&1 | tail -15
[ -f monitor.bpf.o ] && echo "OK compilou" || { echo "FALHOU compilacao"; exit 1; }

echo "== 3. carregar com bpftool (autoattach)"
rm -rf /sys/fs/bpf/monitor
bpftool prog loadall monitor.bpf.o /sys/fs/bpf/monitor autoattach 2>&1 | tail -5
bpftool prog show name trace_tcp_sendmsg 2>&1 | head -3

echo "== 4. gerar trafego na porta 8080"
python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 & SRV=$!
sleep 1
for i in 1 2 3 4 5; do curl -s http://127.0.0.1:8080/ >/dev/null; done

echo "== 5. ler o mapa (texto)"
bpftool map dump name bytes_por_porta 2>&1 | head -12
echo "== 5b. ler o mapa (JSON)"
bpftool -j map dump name bytes_por_porta 2>&1 | head -c 600; echo

echo "== 6. exporter Python"
cat > exporter.py <<'EOF'
import json
import subprocess
import time

from prometheus_client import start_http_server
from prometheus_client.core import CounterMetricFamily, REGISTRY

PORTAS = {80, 443, 8080}  # portas de servico de interesse


def ler_mapa(nome):
    saida = subprocess.run(["bpftool", "-j", "map", "dump", "name", nome],
                           capture_output=True, text=True, check=True).stdout
    return json.loads(saida)


class Coletor:
    def collect(self):
        m = CounterMetricFamily("ebpf_tcp_bytes_enviados",
                                "Bytes enviados por porta de destino",
                                labels=["porta"])
        for entrada in ler_mapa("bytes_por_porta"):
            f = entrada["formatted"]
            if f["key"] in PORTAS:
                m.add_metric([str(f["key"])], f["value"])
        yield m


REGISTRY.register(Coletor())
start_http_server(8000)
while True:
    time.sleep(1)
EOF
python3 exporter.py > exporter.log 2>&1 & EXP=$!
sleep 2
curl -s http://127.0.0.1:8000/metrics | grep -E '^ebpf_tcp|^# (HELP|TYPE) ebpf_tcp'
echo "--- log do exporter:"; head -5 exporter.log
echo "--- series publicadas (esperado: so portas 80/443/8080):"
curl -s http://127.0.0.1:8000/metrics | grep -c '^ebpf_tcp_bytes_enviados_total'
echo "== fim"
