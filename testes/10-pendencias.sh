#!/usr/bin/env bash
# Rodada 10: trechos que ficaram com "TODO: validar com sudo" nos Manuais 2 e 3.
#   Manual 3: histograma netif_receive_skb (cap. 11), netem + retransmissoes (cap. 11),
#             firewall de saida em TC (cap. 7), limitador de SYN em XDP (cap. 7)
#   Manual 2: opensnoop filtrado por grep como root e alerta de finit_module (cap. 9)
# Rodar na raiz do repositorio:
#   sudo bash testes/10-pendencias.sh 2>&1 | tee testes/resultados/10-pendencias.txt
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
for c in clang bpftool ip curl python3 bpftrace tc; do command -v $c >/dev/null || { echo "FALTA $c"; exit 1; }; done
SRC="$(cd "$(dirname "$0")/redes" && pwd)"
W=/tmp/ebpf-pend; rm -rf $W; mkdir -p $W
NS=pod1; HIF=veth-host; PIF=veth-pod; HIP=10.200.0.1; PIP=10.200.0.2
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
nok() { echo "FAIL  $1"; fail=$((fail+1)); }
cleanup() {
  kill $SRV 2>/dev/null
  ip netns del $NS 2>/dev/null
  modprobe -r dummy 2>/dev/null
  rm -rf /sys/fs/bpf/pend
}
trap cleanup EXIT
ARCHINC=/usr/include/$(uname -m)-linux-gnu
for p in tc_egress_fw syn_guard; do
  clang -target bpf -O2 -g -Wall -I$ARCHINC -c $SRC/$p.bpf.c -o $W/$p.bpf.o 2>/dev/null || echo "compilacao de $p falhou"
done

# cena SAIDA ESPERA CARGA CMD... : inicia CMD, espera anexar, roda CARGA, espera, SIGINT
cena() {
  local out=$1 espera=$2 carga=$3; shift 3
  : > "$out"
  timeout -s INT 60 "$@" > "$out" 2>&1 &
  local pid=$! n=0
  until grep -qE "Attached|PID|Tracing" "$out" || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
  sleep 1; eval "$carga"; sleep "$espera"
  kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null
}

echo "== laboratorio netns $NS + veth"
ip netns add $NS
ip link add $HIF type veth peer name $PIF; ip link set $PIF netns $NS
ip addr add $HIP/24 dev $HIF; ip link set $HIF up
ip netns exec $NS ip addr add $PIP/24 dev $PIF
ip netns exec $NS ip link set $PIF up; ip netns exec $NS ip link set lo up
python3 -m http.server 8099 --bind $HIP --directory /tmp >/dev/null 2>&1 &
SRV=$!; sleep 1
ip netns exec $NS curl -s -m 3 -o /dev/null http://$HIP:8099/ && ok "lab: curl pod -> host:8099" || nok "lab: curl pod -> host:8099"

echo "== A. histograma de tamanho de pacotes (cap. 11, lst:ex-pkt-hist)"
cena $W/a.out 1 "ip netns exec $NS ping -c 3 -W 1 $HIP >/dev/null" \
  bpftrace -e 'tracepoint:net:netif_receive_skb /str(args->name) == "veth-host"/ { @len = hist(args->len); }'
tr -d '\000' < $W/a.out | grep -vE "warning|WARNING|HINT|\^~|include/" | head -12
grep -q "@len" $W/a.out && ok "histograma netif_receive_skb" || nok "histograma netif_receive_skb"

echo "== B. netem + retransmissoes (cap. 11, lst:ex-retrans)"
if modprobe sch_netem 2>/dev/null; then
  ip netns exec $NS tc qdisc add dev $PIF root netem loss 20%
  cena $W/b.out 1 "ip netns exec $NS curl -s -m 5 -o /dev/null http://$HIP:8099/; ip netns exec $NS curl -s -m 5 -o /dev/null http://$HIP:8099/" \
    bpftrace -e 'tracepoint:tcp:tcp_retransmit_skb { printf("%s sport=%d dport=%d\n", comm, args->sport, args->dport); }'
  ip netns exec $NS tc qdisc del dev $PIF root
  tr -d '\000' < $W/b.out | grep -E "Attached|sport=" | head -8
  grep -q "sport=" $W/b.out && ok "retransmissoes observadas" || echo "INFO  nenhuma retransmissao nesta rodada (a perda e aleatoria)"
else
  echo "INFO  sch_netem indisponivel"
fi

echo "== C. firewall de saida em TC (cap. 7) no veth-pod, regra para a porta 8099"
ip netns exec $NS tc qdisc add dev $PIF clsact
if ip netns exec $NS tc filter add dev $PIF egress bpf da obj $W/tc_egress_fw.bpf.o sec tc 2>$W/c.err; then
  ok "verificador aceitou tc_egress_fw (tc filter add)"
  ip netns exec $NS tc filter show dev $PIF egress | head -3
  ID=$(bpftool map show name saida_proibida | head -1 | cut -d: -f1)
  # chave u16 em ordem de bytes do host (little-endian): 8099 = 0x1fa3 -> a3 1f
  bpftool map update id $ID key hex a3 1f value hex 00 00 00 00 00 00 00 00
  ip netns exec $NS curl -s -m 3 -o /dev/null http://$HIP:8099/ && nok "porta 8099 deveria estar bloqueada" || ok "curl bloqueado pelo tc_egress_fw"
  echo "-- contador da regra:"; bpftool map dump id $ID | tr -d '\n ' ; echo
  bpftool map delete id $ID key hex a3 1f
  ip netns exec $NS curl -s -m 3 -o /dev/null http://$HIP:8099/ && ok "curl volta apos remover a regra" || nok "curl volta apos remover a regra"
else
  nok "verificador rejeitou tc_egress_fw"; cat $W/c.err
fi

echo "== D. limitador de SYN em XDP (cap. 7): so a aceitacao pelo verificador"
mkdir -p /sys/fs/bpf/pend
if bpftool prog loadall $W/syn_guard.bpf.o /sys/fs/bpf/pend/syn pinmaps /sys/fs/bpf/pend/synmaps 2>$W/d.err; then
  ok "verificador aceitou syn_guard (bpftool prog loadall)"
  bpftool prog show pinned /sys/fs/bpf/pend/syn/* 2>/dev/null | head -2
else
  nok "verificador rejeitou syn_guard"; head -15 $W/d.err
fi

echo "== E. Manual 2, cap. 9: opensnoop | grep como root"
( timeout -s INT 8 sh -c "opensnoop-libbpf | grep --line-buffered -E '/etc/(shadow|passwd)' > $W/e.out" ) &
sleep 4; cat /etc/shadow > /dev/null; cat /etc/passwd > /dev/null; wait
tr -d '\000' < $W/e.out | head -6
grep -q "/etc/shadow" $W/e.out && ok "opensnoop|grep viu /etc/shadow (root)" || nok "opensnoop|grep viu /etc/shadow (root)"

echo "== F. Manual 2, cap. 9: alerta de finit_module"
modprobe -r dummy 2>/dev/null
cena $W/f.out 1 "modprobe dummy" \
  bpftrace -e 'tracepoint:syscalls:sys_enter_finit_module { printf("[ALERTA] %s (pid=%d uid=%d) carregou um modulo\n", comm, pid, uid); }'
tr -d '\000' < $W/f.out | grep -E "Attached|ALERTA" | head -4
grep -q ALERTA $W/f.out && ok "alerta de finit_module" || nok "alerta de finit_module"

echo "== RESUMO: $pass PASS, $fail FAIL"
