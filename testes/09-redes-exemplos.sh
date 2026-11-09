#!/usr/bin/env bash
# Rodada 9 (Manual 3, eBPF para Redes): os tres exemplos do cap. 11 (captura de pacotes,
# monitoramento de conexoes, filtragem) em um laboratorio com network namespace + veth.
# Pre-requisitos: sudo apt install -y clang libbpf-dev libelf-dev zlib1g-dev bpftool bpftrace tcpdump iproute2 curl
#                 (opcional: libbpf-tools ou bpfcc-tools para o exemplo 2)
# Rodar com: sudo bash testes/09-redes-exemplos.sh 2>&1 | tee testes/resultados/09-redes-exemplos.txt
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
for c in clang bpftool ip ping curl python3; do command -v $c >/dev/null || { echo "FALTA $c"; exit 1; }; done

SRC="$(cd "$(dirname "$0")/redes" && pwd)"
W=/tmp/ebpf-redes-teste; rm -rf $W; mkdir -p $W; cd $W
NS=pod1; HOSTIF=veth-host; PODIF=veth-pod; HOSTIP=10.200.0.1; PODIP=10.200.0.2
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
nok()  { echo "FAIL  $1"; fail=$((fail+1)); }
check() { local rot="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$rot"; else nok "$rot"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  kill $SRV 2>/dev/null
  bpftool net detach xdpgeneric dev $HOSTIF 2>/dev/null
  ip netns del $NS 2>/dev/null
  rm -rf /sys/fs/bpf/redes
}
trap cleanup EXIT

echo "== 0. compilar os programas (clang -target bpf)"
ARCHINC=/usr/include/$(uname -m)-linux-gnu
for p in fw_xdp pkt_trace syn_guard tc_egress_fw; do
  check "compila $p" clang -target bpf -O2 -g -Wall -I$ARCHINC -c $SRC/$p.bpf.c -o $W/$p.bpf.o
done
check "skeleton fw_xdp" bash -c "bpftool gen skeleton $W/fw_xdp.bpf.o > $W/fw_xdp.skel.h"
check "compila fw_loader" gcc -O2 -Wall -I$W $SRC/fw_loader.c -o $W/fw_loader -lbpf -lelf -lz

echo "== laboratorio: netns $NS + veth ($HOSTIF <-> $PODIF)"
ip netns add $NS
ip link add $HOSTIF type veth peer name $PODIF
ip link set $PODIF netns $NS
ip addr add $HOSTIP/24 dev $HOSTIF; ip link set $HOSTIF up
ip netns exec $NS ip addr add $PODIP/24 dev $PODIF
ip netns exec $NS ip link set $PODIF up; ip netns exec $NS ip link set lo up
check "ping pod -> host (sem eBPF)" ip netns exec $NS ping -c 2 -W 2 $HOSTIP

echo "== 1. captura e analise de pacotes (pkt_trace + tcpdump)"
mkdir -p /sys/fs/bpf/redes
bpftool prog loadall $W/pkt_trace.bpf.o /sys/fs/bpf/redes/pt
bpftool net attach xdpgeneric pinned /sys/fs/bpf/redes/pt/pkt_trace dev $HOSTIF
bpftool net show dev $HOSTIF
timeout 6 bpftool prog tracelog > $W/tracelog.txt 2>&1 &
TL=$!
timeout 6 tcpdump -n -i $HOSTIF -c 3 icmp > $W/tcpdump.txt 2>&1 &
sleep 1
ip netns exec $NS ping -c 3 -W 2 $HOSTIP >/dev/null
wait $TL 2>/dev/null
echo "-- tracelog (filtrado)"; grep -E 'proto=1|tcp ' $W/tracelog.txt | head -6
echo "-- tcpdump"; head -6 $W/tcpdump.txt
grep -q 'proto=1' $W/tracelog.txt && ok "bpf_printk registrou ICMP (proto=1)" || nok "bpf_printk registrou ICMP (proto=1)"
grep -q 'ICMP' $W/tcpdump.txt && ok "tcpdump viu o mesmo ICMP" || nok "tcpdump viu o mesmo ICMP"
bpftool net detach xdpgeneric dev $HOSTIF
rm -rf /sys/fs/bpf/redes/pt

echo "== 2. monitoramento de conexoes"
python3 -m http.server 8099 --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!
sleep 1
CON=""
have tcpconnect-libbpf && CON=tcpconnect-libbpf
[ -z "$CON" ] && have tcpconnect-bpfcc && CON=tcpconnect-bpfcc
LIFE=""
have tcplife-libbpf && LIFE=tcplife-libbpf
[ -z "$LIFE" ] && have tcplife-bpfcc && LIFE=tcplife-bpfcc
[ -n "$CON" ]  && { timeout -s INT 6 $CON  > $W/tcpconnect.txt 2>&1 & }
[ -n "$LIFE" ] && { timeout -s INT 6 $LIFE > $W/tcplife.txt   2>&1 & }
timeout -s INT 6 bpftrace -e 'tracepoint:sock:inet_sock_set_state /args->newstate == 1/ { printf("%s -> dport %d\n", comm, args->dport); }' > $W/bt-estados.txt 2>&1 &
sleep 2
for i in 1 2 3; do curl -s -o /dev/null http://127.0.0.1:8099/; done
sleep 5
echo "-- ss (conexoes de escuta)"; ss -ltn 'sport = :8099'
if [ -n "$CON" ]; then echo "-- $CON"; head -5 $W/tcpconnect.txt
  grep -q 8099 $W/tcpconnect.txt && ok "$CON viu conexao para 8099" || nok "$CON viu conexao para 8099"
else echo "SKIP  tcpconnect nao instalado"; fi
if [ -n "$LIFE" ]; then echo "-- $LIFE"; head -5 $W/tcplife.txt
  grep -q 8099 $W/tcplife.txt && ok "$LIFE viu conexao 8099" || nok "$LIFE viu conexao 8099"
else echo "SKIP  tcplife nao instalado"; fi
echo "-- bpftrace inet_sock_set_state"; head -5 $W/bt-estados.txt
grep -q 8099 $W/bt-estados.txt && ok "bpftrace viu conexao para 8099" || nok "bpftrace viu conexao para 8099"
kill $SRV 2>/dev/null

echo "== 3. filtragem de trafego (fw_xdp na $HOSTIF)"
mkdir -p /sys/fs/bpf/redes
bpftool prog loadall $W/fw_xdp.bpf.o /sys/fs/bpf/redes/fw pinmaps /sys/fs/bpf/redes/fw/maps
bpftool net attach xdpgeneric pinned /sys/fs/bpf/redes/fw/xdp_fw dev $HOSTIF
bpftool net show dev $HOSTIF
check "ping passa com firewall vazio" ip netns exec $NS ping -c 2 -W 2 $HOSTIP
bpftool map update pinned /sys/fs/bpf/redes/fw/maps/blocklist key hex 0a c8 00 02 value hex 01 00 00 00
bpftool map dump pinned /sys/fs/bpf/redes/fw/maps/blocklist
if ip netns exec $NS ping -c 2 -W 2 $HOSTIP >/dev/null 2>&1; then nok "ping bloqueado pela blocklist"; else ok "ping bloqueado pela blocklist"; fi
echo "-- contadores (indice 0 = aceitos, 1 = descartados, somados por CPU)"; bpftool map dump pinned /sys/fs/bpf/redes/fw/maps/stats
bpftool map delete pinned /sys/fs/bpf/redes/fw/maps/blocklist key hex 0a c8 00 02
check "ping volta apos remover regra" ip netns exec $NS ping -c 2 -W 2 $HOSTIP
bpftool net detach xdpgeneric dev $HOSTIF
check "ping apos desanexar" ip netns exec $NS ping -c 2 -W 2 $HOSTIP

echo "== 3b. carregador libbpf (fw_loader) por 3 s"
timeout -s INT 3 $W/fw_loader $HOSTIF $PODIP > $W/loader.txt 2>&1
cat $W/loader.txt | head -4
grep -q 'aceitos=' $W/loader.txt && ok "fw_loader imprimiu contadores" || nok "fw_loader imprimiu contadores"

echo
echo "RESUMO: $pass PASS, $fail FAIL"
