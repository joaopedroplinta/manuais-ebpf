#!/usr/bin/env bash
# Rodada 7: cenarios do cap. 8 (Exemplos Praticos). Rodar com: sudo bash testes/07-exemplos-praticos.sh 2>&1 | tee testes/resultados/07-exemplos-praticos.txt
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
PORTA=8099

# cena SAIDA ESPERA CARGA CMD... : inicia CMD, espera ate ele escrever algo (anexado),
# roda CARGA, espera ESPERA s para o fluxo/intervalo e encerra com SIGINT.
cena() {
  local out=$1 espera=$2 carga=$3; shift 3
  : > "$out"
  timeout -s INT 60 "$@" > "$out" 2>&1 &
  local pid=$! n=0
  until grep -qE "Attached|PID|Tracing" "$out" || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
  sleep 1
  eval "$carga"
  sleep "$espera"
  kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null
}
filtra() { grep -vE "warning|WARNING|HINT|^ *[0-9]+ \||\^~|include/|^~+$" "$1" | head -${2:-15}; }

echo "== A. execsnoop: processos curtos"
cena /tmp/ex-a.out 1 'for i in 1 2 3; do date > /dev/null; sleep 0.2; done' execsnoop-libbpf
grep -E "PCOMM|date|sleep" /tmp/ex-a.out

echo "== A2. execve com o nome do arquivo (carga: 3x date)"
cena /tmp/ex-a2.out 1 'for i in 1 2 3; do date > /dev/null; done' \
  bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%d %s -> %s\n", pid, comm, str(args->filename)); }'
filtra /tmp/ex-a2.out

echo "== A3. contagem de execve por processo (carga: 3x date)"
cena /tmp/ex-a3.out 1 'for i in 1 2 3; do date > /dev/null; done' \
  bpftrace -e 'tracepoint:syscalls:sys_enter_execve { @[comm] = count(); }'
filtra /tmp/ex-a3.out

echo "== B. servidor http (porta $PORTA)"
echo "quem usa a 8080:"; ss -ltnp 2>/dev/null | grep -E ":8080 " || echo "  ninguem"
python3 -m http.server $PORTA --directory /tmp > /tmp/ex-srv.log 2>&1 &
SRV=$!; sleep 1
kill -0 $SRV 2>/dev/null || { echo "servidor nao subiu:"; cat /tmp/ex-srv.log; }
echo "SRV=$SRV comm=$(ps -o comm= -p $SRV) tgid=$(awk '/^Tgid/{print $2}' /proc/$SRV/status)"
CURLS="for i in 1 2 3; do curl -s http://localhost:$PORTA/ > /dev/null; done"
echo "-- B1 opensnoop -p"; cena /tmp/ex-b1.out 1 "$CURLS" opensnoop-libbpf -p "$SRV"; head -15 /tmp/ex-b1.out
echo "-- B2 opensnoop sem -p, filtrado por comm"; cena /tmp/ex-b2.out 1 "$CURLS" opensnoop-libbpf; grep -E "PID|python" /tmp/ex-b2.out | head -15
echo "-- B3 opensnoop -n python3"; cena /tmp/ex-b3.out 1 "$CURLS" opensnoop-libbpf -n python3; head -15 /tmp/ex-b3.out
echo "-- B4 syscount -p"; cena /tmp/ex-b4.out 3 "$CURLS" syscount-libbpf -p "$SRV" -i 2; head -20 /tmp/ex-b4.out
echo "-- B6 bpftrace por pid"; cena /tmp/ex-b6.out 1 "$CURLS" bpftrace -e "tracepoint:raw_syscalls:sys_enter /pid == $SRV/ { @[comm] = count(); }"; filtra /tmp/ex-b6.out 12
echo "-- B5 syscount sem -p"; cena /tmp/ex-b5.out 3 "$CURLS" syscount-libbpf -i 2; head -12 /tmp/ex-b5.out

echo "== C. tcplife -L $PORTA"
cena /tmp/ex-c.out 1 'for i in $(seq 1 5); do curl -s http://localhost:$PORTA/ > /dev/null; done' tcplife-libbpf -L $PORTA
head -10 /tmp/ex-c.out
kill "$SRV" 2>/dev/null

echo "== D. USDT: modulos importados"
P=/usr/bin/python3.14
cena /tmp/ex-d.out 1 "$P -c 'import json, csv'" \
  bpftrace -e "usdt:$P:python:import__find__load__start { printf(\"%s\\n\", str(arg0)); }"
filtra /tmp/ex-d.out 12
echo "== fim"
